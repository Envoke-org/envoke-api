package common

func AssertData(v interface{}) Data {
	if d, ok := v.(Data); ok {
		return d
	}
	if d, ok := v.(map[string]interface{}); ok {
		return Data(d)
	}
	return nil
}

func AssertDataSlice(v interface{}) []Data {
	if slice, ok := v.([]Data); ok {
		return slice
	}
	if slice, ok := v.([]interface{}); ok {
		datas := make([]Data, len(slice))
		for i, s := range slice {
			datas[i] = AssertData(s)
		}
		return datas
	}
	return nil
}

func AssertInt(v interface{}) int {
	if n, ok := v.(int); ok {
		return n
	}
	if n, ok := v.(float64); ok {
		return int(n)
	}
	return 0
}

func AssertStr(v interface{}) string {
	if str, ok := v.(string); ok {
		return str
	}
	return ""
}

func AssertStrSlice(v interface{}) []string {
	if slice, ok := v.([]string); ok {
		return slice
	}
	if slice, ok := v.([]interface{}); ok {
		strs := make([]string, len(slice))
		for i, s := range slice {
			strs[i] = s.(string)
		}
		return strs
	}
	return nil
}
