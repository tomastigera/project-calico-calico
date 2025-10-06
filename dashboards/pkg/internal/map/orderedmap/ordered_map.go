// Copyright (c) 2025 Tigera, Inc. All rights reserved.

package orderedmap

// OrderedMap is a generic ordered map that preserves insertion order while allowing O(1) lookups by key.
type OrderedMap[K comparable, V any] struct {
	order []K
	items map[K]V
}

func New[K comparable, V any]() *OrderedMap[K, V] {
	return &OrderedMap[K, V]{
		order: make([]K, 0),
		items: make(map[K]V),
	}
}

func (o *OrderedMap[K, V]) Put(k K, v V) {
	if _, exists := o.items[k]; !exists {
		o.order = append(o.order, k)
	}
	o.items[k] = v
}

func (o *OrderedMap[K, V]) Get(k K) (V, bool) {
	v, ok := o.items[k]
	return v, ok
}

func (o *OrderedMap[K, V]) ValuesInOrder() []V {
	res := make([]V, 0, len(o.order))
	for _, k := range o.order {
		if v, ok := o.items[k]; ok {
			res = append(res, v)
		}
	}
	return res
}
