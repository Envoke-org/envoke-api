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
