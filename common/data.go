package common

type Data map[string]interface{}

func (d Data) Get(key string) interface{}        { return d[key] }
func (d Data) Set(key string, value interface{}) { d[key] = value }
func (d Data) Clear(key string)                  { d[key] = nil }
func (d Data) Delete(key string)                 { delete(d, key) }

func (d Data) GetData(key string) Data         { return AssertData(d.Get(key)) }
func (d Data) GetDataSlice(key string) []Data  { return AssertDataSlice(d.Get(key)) }
func (d Data) GetInt(key string) int           { return AssertInt(d.Get(key)) }
func (d Data) GetStr(key string) string        { return AssertStr(d.Get(key)) }
func (d Data) GetStrSlice(key string) []string { return AssertStrSlice(d.Get(key)) }

func (d Data) GetInnerValue(keys ...string) (v interface{}) {
	inner := d
	for i, k := range keys {
		if i == len(keys)-1 {
			v = inner.Get(k)
			break
		}
		inner = inner.GetData(k)
	}
	return
}

func (d Data) SetInnerValue(v interface{}, keys ...string) {
	inner := d
	for i, k := range keys {
		if i == len(keys)-1 {
			inner.Set(k, v)
			return
		}
		inner = inner.GetData(k)
	}
}

func (d Data) GetInnerStr(keys ...string) string {
	return AssertStr(d.GetInnerValue(keys...))
}

func (d Data) GetInnerData(keys ...string) Data {
	return AssertData(d.GetInnerValue(keys...))
}
