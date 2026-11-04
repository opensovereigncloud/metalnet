// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and IronCore contributors
// SPDX-License-Identifier: Apache-2.0

package orchestrator

import (
	"context"

	metalnetv1alpha1 "github.com/ironcore-dev/metalnet/api/v1alpha1"
	metalnetapply "github.com/ironcore-dev/metalnet/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// writeEntry applies this host's entry of a Network's encryption status, or removes it if entry is
// nil. It uses server-side apply with a field manager per node: a merge patch replaces the whole
// list, and hosts would overwrite each other.
func (o *Orchestrator) writeEntry(ctx context.Context, key types.NamespacedName, entry *metalnetv1alpha1.NetworkEncryptionStatus) error {
	network := metalnetapply.Network(key.Name, key.Namespace)
	if entry != nil {
		applied := metalnetapply.NetworkEncryptionStatus().WithNodeName(entry.NodeName).WithState(entry.State)
		if entry.Message != "" {
			applied = applied.WithMessage(entry.Message)
		}
		network = network.WithStatus(metalnetapply.NetworkStatus().WithEncryption(applied))
	}
	return o.client.Status().Apply(ctx, network, client.FieldOwner("metalnet-"+o.nodeName), client.ForceOwnership)
}
