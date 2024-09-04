/*
 * Teleport
 * Copyright (C) 2023  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package peer

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math"
	"net"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/gravitational/trace"
	"github.com/gravitational/trace/trail"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api"
	"github.com/gravitational/teleport/api/metadata"
	"github.com/gravitational/teleport/api/utils/grpc/interceptors"
	peerv0c "github.com/gravitational/teleport/gen/proto/go/teleport/lib/proxy/peer/v0/peerv0connect"
	"github.com/gravitational/teleport/lib/utils"
)

const (
	peerKeepAlive = time.Second * 10
	peerTimeout   = time.Second * 20
)

// ServerConfig configures a Server instance.
type ServerConfig struct {
	Listener      net.Listener
	TLSConfig     *tls.Config
	ClusterDialer ClusterDialer
	Log           logrus.FieldLogger
	ClusterName   string

	// service is a custom ProxyServiceHandler configurable for testing
	// purposes.
	service peerv0c.ProxyServiceHandler
}

// checkAndSetDefaults checks and sets default values
func (c *ServerConfig) checkAndSetDefaults() error {
	if c.Log == nil {
		c.Log = logrus.New()
	}
	c.Log = c.Log.WithField(
		teleport.ComponentKey,
		teleport.Component(teleport.ComponentProxy, "peer"),
	)

	if c.Listener == nil {
		return trace.BadParameter("missing listener")
	}

	if c.ClusterDialer == nil {
		return trace.BadParameter("missing cluster dialer server")
	}

	if c.ClusterName == "" {
		return trace.BadParameter("missing cluster name")
	}

	if c.TLSConfig == nil {
		return trace.BadParameter("missing tls config")
	}
	c.TLSConfig.ClientAuth = tls.RequireAndVerifyClientCert

	if c.service == nil {
		c.service = &proxyService{
			clusterDialer: c.ClusterDialer,
			log:           c.Log,
		}
	}

	return nil
}

// Server is a proxy service server using grpc and tls.
type Server struct {
	config ServerConfig
	server *grpc.Server
}

// NewServer creates a new proxy server instance.
func NewServer(config ServerConfig) (*Server, error) {
	err := config.checkAndSetDefaults()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	metrics, err := newServerMetrics()
	if err != nil {
		return nil, trace.Wrap(err)
	}

	reporter := newReporter(metrics)

	server := grpc.NewServer(
		grpc.Creds(newServerCredentials(credentials.NewTLS(config.TLSConfig))),
		grpc.StatsHandler(newStatsHandler(reporter)),
		grpc.ChainStreamInterceptor(metadata.StreamServerInterceptor, interceptors.GRPCServerStreamErrorInterceptor),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    peerKeepAlive,
			Timeout: peerTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             peerKeepAlive,
			PermitWithoutStream: true,
		}),

		// the proxy peering server uses transport authentication to verify that
		// the client is another Teleport proxy, and the proxy peering service
		// is intended for mass connection routing (spawning an unbounded amount
		// of streams of unbounded duration), so adding a limit on concurrent
		// streams (for example to prevent CVE-2023-44487, see
		// https://github.com/grpc/grpc-go/pull/6703 ) is unnecessary and
		// counterproductive to the functionality of proxy peering
		grpc.MaxConcurrentStreams(math.MaxUint32),
	)

	handlerOptions := connect.WithHandlerOptions(
		connect.WithCompression("gzip", nil, nil),
		connect.WithInterceptors(addVersionInterceptor{}, traceErrorsInterceptor{}),
	)

	mux := http.NewServeMux()
	mux.Handle(
		peerv0c.NewProxyServiceHandler(config.service, handlerOptions),
	)

	return &Server{
		config: config,
		server: server,
	}, nil
}

// Serve starts the proxy server.
func (s *Server) Serve() error {
	if err := s.server.Serve(s.config.Listener); err != nil {
		if errors.Is(err, grpc.ErrServerStopped) ||
			utils.IsUseOfClosedNetworkError(err) {
			return nil
		}
		return trace.Wrap(err)
	}
	return nil
}

// Close closes the proxy server immediately.
func (s *Server) Close() error {
	s.server.Stop()
	return nil
}

// Shutdown does a graceful shutdown of the proxy server.
func (s *Server) Shutdown() error {
	s.server.GracefulStop()
	return nil
}

type addVersionInterceptor struct{}

var _ connect.Interceptor = addVersionInterceptor{}

// WrapStreamingClient implements [connect.Interceptor].
func (addVersionInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, s connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, s)
		conn.RequestHeader().Set(metadata.VersionKey, api.Version)
		return conn
	}
}

// WrapStreamingHandler implements [connect.Interceptor].
func (addVersionInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		conn.ResponseHeader().Set(metadata.VersionKey, api.Version)
		return next(ctx, conn)
	}
}

// WrapUnary implements [connect.Interceptor].
func (addVersionInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set(metadata.VersionKey, api.Version)
		return next(ctx, req)
	}
}

type traceErrorsInterceptor struct{}

var _ connect.Interceptor = traceErrorsInterceptor{}

type traceErrorsStreamingClientConn struct {
	connect.StreamingClientConn
}

func (c *traceErrorsStreamingClientConn) Send(msg any) error {
	return fromConnectRPC(c.StreamingClientConn.Send(msg))
}

func (c *traceErrorsStreamingClientConn) CloseRequest() error {
	return fromConnectRPC(c.StreamingClientConn.CloseRequest())
}

func (c *traceErrorsStreamingClientConn) Receive(msg any) error {
	return fromConnectRPC(c.StreamingClientConn.Receive(msg))
}

func (c *traceErrorsStreamingClientConn) CloseResponse() error {
	return fromConnectRPC(c.StreamingClientConn.CloseResponse())
}

// WrapStreamingClient implements connect.Interceptor.
func (traceErrorsInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, s connect.Spec) connect.StreamingClientConn {
		return &traceErrorsStreamingClientConn{
			StreamingClientConn: next(ctx, s),
		}
	}
}

type traceErrorsStreamingHandlerConn struct {
	connect.StreamingHandlerConn
}

func (c *traceErrorsStreamingHandlerConn) Send(msg any) error {
	return fromConnectRPC(c.StreamingHandlerConn.Send(msg))
}

func (c *traceErrorsStreamingHandlerConn) Receive(msg any) error {
	return fromConnectRPC(c.StreamingHandlerConn.Receive(msg))
}

// WrapStreamingHandler implements connect.Interceptor.
func (traceErrorsInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return toConnectRPC(next(ctx, &traceErrorsStreamingHandlerConn{
			StreamingHandlerConn: conn,
		}))
	}
}

// WrapUnary implements connect.Interceptor.
func (traceErrorsInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		resp, err := next(ctx, req)
		err = fromConnectRPC(err)
		return resp, err
	}
}

func toConnectRPC(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, io.EOF) {
		return err
	}
	err = trail.ToGRPC(err)
	return connect.NewError(connect.Code(status.Code(err)), err)
}

func fromConnectRPC(err error) error {
	if err == nil {
		return nil
	}
	if cErr := (*connect.Error)(nil); errors.As(err, &cErr) {
		return trail.FromGRPC(status.Error(codes.Code(cErr.Code()), cErr.Message()))
	}
	return err
}
