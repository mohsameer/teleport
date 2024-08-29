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

package web

import (
	"context"

	"github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/entitlements"
)

// SetClusterFeatures sets the flags for supported and unsupported features
func (h *Handler) SetClusterFeatures(features proto.Features) {
	h.Mutex.Lock()
	defer h.Mutex.Unlock()

	entitlements.BackfillFeatures(&features)
	h.clusterFeatures = features
}

// GetClusterFeatures returns flags for supported and unsupported features.
func (h *Handler) GetClusterFeatures() proto.Features {
	h.Mutex.Lock()
	defer h.Mutex.Unlock()

	return h.clusterFeatures
}

// startFeatureWatcher periodically pings the auth server and updates `clusterFeatures`.
func (h *Handler) startFeatureWatcher() {
	h.featureWatcherOnce.Do(func() {
		ticker := h.clock.NewTicker(h.cfg.FeatureWatchInterval)
		h.log.WithField("interval", h.cfg.FeatureWatchInterval).Info("Proxy handler features watcher has started")
		ctx := context.Background()

		defer ticker.Stop()
		for {
			select {
			case <-ticker.Chan():
				h.log.Info("Pinging auth server for features")
				f, err := h.cfg.ProxyClient.Ping(ctx)
				if err != nil {
					h.log.WithError(err).Error("Auth server ping failed")
					continue
				}

				h.SetClusterFeatures(*f.ServerFeatures)
				h.log.Debug("Done updating proxy features")
			case <-h.featureWatcherStop:
				h.log.Info("Feature service has stopped")
				return
			}
		}
	})
}

// stopFeatureWatcher stops the feature watcher
func (h *Handler) stopFeatureWatcher() {
	close(h.featureWatcherStop)
}
