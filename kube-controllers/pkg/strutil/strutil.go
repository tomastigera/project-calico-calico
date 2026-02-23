// Copyright (c) 2019-2020 Tigera, Inc. All rights reserved.

package strutil

import "slices"

func InList(str string, list []string) bool {
	return slices.Contains(list, str)
}
