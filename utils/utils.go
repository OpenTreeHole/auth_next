package utils

func SliceReverse[T any](source []T) []T {
	length := len(source)
	reversed := make([]T, length)
	for i := range source {
		reversed[i] = source[length-i-1]
	}
	return reversed
}

func InUnorderedSlice[T comparable](slice []T, target T) bool {
	for _, elem := range slice {
		if target == elem {
			return true
		}
	}
	return false
}
