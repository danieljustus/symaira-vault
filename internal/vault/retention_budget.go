package vault

import "reflect"

// Conservative retention accounting bounds nodes and byte copies before cache
// or index collection. This is deliberately not a runtime RSS measurement.
func retainedDataCost(value any, remaining int) (int, bool) {
	used := 0
	add := func(cost int) bool {
		if cost > remaining-used {
			return false
		}
		used += cost
		return true
	}
	var count func(reflect.Value) bool
	count = func(value reflect.Value) bool {
		if !add(256) {
			return false
		}
		if !value.IsValid() {
			return true
		}
		switch value.Kind() {
		case reflect.Invalid, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr, reflect.Float32, reflect.Float64:
			return true
		case reflect.Complex64, reflect.Complex128, reflect.Chan, reflect.Func, reflect.UnsafePointer:
			return false
		case reflect.Interface, reflect.Pointer:
			if !value.IsNil() {
				return count(value.Elem())
			}
		case reflect.String:
			return add(6 * value.Len())
		case reflect.Map:
			iter := value.MapRange()
			for iter.Next() {
				if !count(iter.Key()) || !count(iter.Value()) {
					return false
				}
			}
		case reflect.Slice, reflect.Array:
			for i := 0; i < value.Len(); i++ {
				if !count(value.Index(i)) {
					return false
				}
			}
		case reflect.Struct:
			for i := 0; i < value.NumField(); i++ {
				if !count(value.Field(i)) {
					return false
				}
			}
		}
		return true
	}
	fits := count(reflect.ValueOf(value))
	return used, fits
}

// ReadCacheCost applies the same fixed retention ceiling to derived UI caches.
// It reports conservative cost without serializing or copying cached values.
func ReadCacheCost(value any) (int, bool) {
	return retainedDataCost(value, maxPseudonymCacheBytes)
}
