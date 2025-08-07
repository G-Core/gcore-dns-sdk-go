package dnssdk

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRecordTypeMX_ToContent(t *testing.T) {
	tests := []struct {
		name string
		mx   RecordTypeMX
		want []any
	}{
		{
			name: "ok",
			mx:   "10 mail.server",
			want: []any{int64(10), "mail.server"},
		},
		{
			name: "wrong",
			mx:   "10",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.mx.ToContent(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRecordTypeCAA_ToContent(t *testing.T) {
	tests := []struct {
		name string
		caa  RecordTypeCAA
		want []any
	}{
		{
			name: "ok",
			caa:  "10 issue aaa",
			want: []any{int64(10), "issue", "aaa"},
		},
		{
			name: "wrong",
			caa:  "10 aa",
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.caa.ToContent(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToContent() = %v, want %v", got, tt.want)
			}
		})
	}
}
func TestRecordTypeHTTPS_SVCB(t *testing.T) {
	// from: dig -t https tls-ech.dev
	// from: dig -t https clickhouse.com
	// the reset are random
	tests := []struct {
		name  string
		https RecordTypeHTTPS_SCVB
		want  []any
		err   error
	}{
		{
			name:  "ech",
			https: "1 . ech=AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA",
			want: []any{
				uint16(1),
				".",
				[]any{"ech", "AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA"},
			},
		},
		{
			name:  "quoted",
			https: `65535 . alpn="h3,h3-29,h2" ipv4hint=172.66.40.249,172.66.43.7 ipv6hint=2606:4700:3108::ac42:28f9,2606:4700:3108::ac42:2b07`,
			want: []any{
				uint16(65535),
				".",
				[]any{"alpn", "h3", "h3-29", "h2"},
				[]any{"ipv4hint", `172.66.40.249`, `172.66.43.7`},
				[]any{"ipv6hint", `2606:4700:3108::ac42:28f9`, `2606:4700:3108::ac42:2b07`},
			},
		},
		{
			name:  "missing priority",
			https: `1 test2.example.com alpn=h2,h3`,
			want: []any{
				uint16(1),
				"test2.example.com",
				[]any{"alpn", "h2", "h3"},
			},
		},
		{

			name:  `duplicate key param`,
			https: `1 test.example.com alpn=h2,h3 alpn=h2,h3`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"alpn", "h2", "h3"},
				[]any{"alpn", "h2", "h3"}, // duplicate
			},
		},
		{
			name:  `no param`,
			https: `0 test.example.com`,
			want: []any{
				uint16(0),
				"test.example.com",
			},
		},
		{
			name:  `invalid param key name`,
			https: `1 test.example.com norfc`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"norfc"},
			},
		},
		{
			name:  `invalid param value type`,
			https: `1 test.example.com alpn=1234`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"alpn", "1234"}, // value must be string, but ignore it anyway
			},
		},
		{
			name:  `invalid target type`,
			https: `1 1234`,
			want: []any{
				uint16(1),
				"1234",
			},
		},
		{
			name:  `invalid priority type`,
			https: `12341234125 a.com`,
			want: []any{
				float64(12341234125), // must be uint16
				"a.com",
			},
		},
		{
			name:  `priority not a number `,
			https: `x a.com`,
			want: []any{
				"x", // must be uint16
				"a.com",
			},
		},
		{
			name:  `invalid mandatory param value`,
			https: `1 test.example.com alpn=h2,h3 mandatory=alpn,notinrfc`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"alpn", "h2", "h3"},
				[]any{"mandatory", "alpn", "notinrfc"}, // should be validated server side
			},
		},
		{
			name:  `invalid mandatory param type`,
			https: `1 test.example.com alpn=h2,h3 mandatory=123`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"alpn", "h2", "h3"},
				[]any{"mandatory", "123"},
			},
		},
		{
			name:  `mandatory param without value`,
			https: `1 test.example.com mandatory`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"mandatory"}, // should be validated server side
			},
		},
		{
			name:  `invalid priority type, no target`,
			https: `#:$5623`,
			want: []any{
				"#:$5623", // must be uint16
			},
		},
		{
			name:  `invalid param type`,
			https: `1 . =====`,
			want: []any{
				uint16(1),
				".",
				[]any{"", "===="}, // should be validated server side
			},
		},
		{
			name:  `invalid alpn param value type`,
			https: `1 test.example.com alpn=h2,h3 alpn=12,34.5`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"alpn", "h2", "h3"},
				[]any{"alpn", "12", "34.5"},
			},
		},
		{
			name:  `without param`,
			https: `1 test.example.com alpn`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"alpn"}, // should be validated server side
			},
		},
		{
			name:  `empty param`,
			https: `1 test.example.com alpn=`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"alpn", ""}, // should be validated server side
			},
		},
		{
			name:  `valid port`,
			https: `1 test.example.com port=1234`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"port", uint16(1234)},
			},
		},
		{
			name:  `invalid port`,
			https: `1 test.example.com port=1234.5`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"port", 1234.5}, // should be validated server side
			},
		},
		{
			name:  `empty port`,
			https: `1 test.example.com port=`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"port", ""}, // should be validated server side
			},
		},
		{
			name:  `non-uint16 port`,
			https: `1 test.example.com port=abcde`,
			want: []any{
				uint16(1),
				"test.example.com",
				[]any{"port", "abcde"}, // should be validated server side
			},
		},
		{
			name:  `no default alpn`,
			https: `3 test2.example.com no-default-alpn`,
			want: []any{
				uint16(3),
				"test2.example.com",
				[]any{"no-default-alpn"},
			},
		},
		{
			name:  "no default alpn having argument",
			https: `2 test3.example.com no-default-alpn=1234.56`,
			want: []any{
				uint16(2),
				"test3.example.com",
				[]any{"no-default-alpn", "1234.56"}, // should be validated server side
			},
		},
		{

			name:  `ipv4hint param`,
			https: `1 test2.example.com ipv4hint=192.168.1.1,192.168.1.2`,
			want: []any{
				uint16(1),
				"test2.example.com",
				[]any{"ipv4hint", "192.168.1.1", "192.168.1.2"},
			},
		},
		{
			name:  `ipv4hint without param`,
			https: `2 test2.example.com ipv4hint`, // should be validated server side
			want: []any{
				uint16(2),
				"test2.example.com",
				[]any{"ipv4hint"},
			},
		},
		{
			name:  `ipv4hint with invalid ip`,
			https: `2 test2.example.com ipv4hint=a.b.c.d`,
			want: []any{
				uint16(2),
				"test2.example.com",
				[]any{"ipv4hint", "a.b.c.d"}, // should be validated server side
			},
		},
		{
			name:  `ipv6hint param`,
			https: `1 test2.example.com ipv6hint=2001:db8::68,2001:db8::69`,
			want: []any{
				uint16(1),
				"test2.example.com",
				[]any{"ipv6hint", "2001:db8::68", "2001:db8::69"},
			},
		},
		{
			name:  `ipv6hint with invalid ip`,
			https: `2 test2.example.com ipv6hint=g:h:i:j:k:l:m:n`,
			want: []any{
				uint16(2),
				"test2.example.com",
				[]any{"ipv6hint", "g:h:i:j:k:l:m:n"}, // should be validated server side
			},
		},
		{
			name:  `ipv6hint without param 2`,
			https: `2 test2.example.com ipv6hint`,
			want: []any{
				uint16(2),
				"test2.example.com",
				[]any{"ipv6hint"}, // should be validated server side
			},
		},
		{
			name:  `ech param`,
			https: `1 test2.example.com ech=AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA`,
			want: []any{
				uint16(1),
				"test2.example.com",
				[]any{"ech", "AEn+DQBFKwAgACABWIHUGj4u+PIggYXcR5JF0gYk3dCRioBW8uJq9H4mKAAIAAEAAQABAANAEnB1YmxpYy50bHMtZWNoLmRldgAA"},
			},
		},
		{
			name:  `ech param with invalid base64`,
			https: `2 test2.example.com ech=AD7+DQA65wXAgAC..AA==`,
			want: []any{
				uint16(2),
				"test2.example.com",
				[]any{"ech", "AD7+DQA65wXAgAC..AA=="}, // should be validated server side
			},
		},
		{
			name:  `ech without param`,
			https: `2 test2.example.com ech`,
			want: []any{
				uint16(2),
				"test2.example.com",
				[]any{"ech"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			content := tt.https.ToContent()
			assert.Equal(t, tt.want, content)
		})
	}
}

func TestRecordTypeAny_ToContent(t *testing.T) {
	tests := []struct {
		name string
		any  RecordTypeAny
		want []any
	}{
		{
			name: "ok",
			any:  "any any 34",
			want: []any{"any any 34"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.any.ToContent(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ToContent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestContentFromValue(t *testing.T) {
	type args struct {
		recordType string
		content    string
	}
	tests := []struct {
		name string
		args args
		want []any
	}{
		{
			name: "mx",
			args: args{
				recordType: "MX",
				content:    "10 mx.com",
			},
			want: []any{int64(10), "mx.com"},
		},
		{
			name: "caa",
			args: args{
				recordType: "CAA",
				content:    "10 issue com",
			},
			want: []any{int64(10), "issue", "com"},
		},
		{
			name: "any",
			args: args{
				recordType: "A",
				content:    "10 issue com",
			},
			want: []any{"10 issue com"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ContentFromValue(tt.args.recordType, tt.args.content); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ContentFromValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResourceMetaIP(t *testing.T) {
	type args struct {
		ips []string
	}
	tests := []struct {
		name string
		args args
		want ResourceMeta
	}{
		{
			name: "one",
			args: args{
				ips: []string{"1.1.1.1"},
			},
			want: ResourceMeta{
				name:     "ip",
				value:    []string{"1.1.1.1"},
				validErr: nil,
			},
		},
		{
			name: "many",
			args: args{
				ips: []string{"1.1.1.1", "1.1.1.2"},
			},
			want: ResourceMeta{
				name:     "ip",
				value:    []string{"1.1.1.1", "1.1.1.2"},
				validErr: nil,
			},
		},
		{
			name: "wrong",
			args: args{
				ips: []string{"1.1.1.1", "sadasd"},
			},
			want: ResourceMeta{
				name:     "",
				value:    nil,
				validErr: fmt.Errorf("wrong ip"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewResourceMetaIP(tt.args.ips...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewResourceMetaIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResourceMetaAsn(t *testing.T) {
	type args struct {
		asn []uint64
	}
	tests := []struct {
		name string
		args args
		want ResourceMeta
	}{
		{
			name: "ok",
			args: args{
				asn: []uint64{1, 2},
			},
			want: ResourceMeta{
				name:     "asn",
				value:    []uint64{1, 2},
				validErr: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewResourceMetaAsn(tt.args.asn...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewResourceMetaAsn() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResourceMetaLatLong(t *testing.T) {
	type args struct {
		latlong string
	}
	tests := []struct {
		name string
		args args
		want ResourceMeta
	}{
		{
			name: "ok",
			args: args{
				latlong: "1,2",
			},
			want: ResourceMeta{
				name:     "latlong",
				value:    []float64{1, 2},
				validErr: nil,
			},
		},
		{
			name: "ok ()",
			args: args{
				latlong: "(1,2)",
			},
			want: ResourceMeta{
				name:     "latlong",
				value:    []float64{1, 2},
				validErr: nil,
			},
		},
		{
			name: "ok []",
			args: args{
				latlong: "[1,2]",
			},
			want: ResourceMeta{
				name:     "latlong",
				value:    []float64{1, 2},
				validErr: nil,
			},
		},
		{
			name: "ok {}",
			args: args{
				latlong: "{1,2}",
			},
			want: ResourceMeta{
				name:     "latlong",
				value:    []float64{1, 2},
				validErr: nil,
			},
		},
		{
			name: "invalid count",
			args: args{
				latlong: "1,2,3",
			},
			want: ResourceMeta{
				name:     "",
				value:    nil,
				validErr: fmt.Errorf("latlong invalid format"),
			},
		},
		{
			name: "invalid lat",
			args: args{
				latlong: "a,2",
			},
			want: ResourceMeta{
				name:  "",
				value: nil,
				validErr: fmt.Errorf("lat is invalid: %w",
					&strconv.NumError{Func: "ParseFloat", Num: "a", Err: strconv.ErrSyntax}),
			},
		},
		{
			name: "invalid long",
			args: args{
				latlong: "1,a",
			},
			want: ResourceMeta{
				name:  "",
				value: nil,
				validErr: fmt.Errorf("long is invalid: %w",
					&strconv.NumError{Func: "ParseFloat", Num: "a", Err: strconv.ErrSyntax}),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewResourceMetaLatLong(tt.args.latlong); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewResourceMetaLatLong() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResourceMetaNotes(t *testing.T) {
	type args struct {
		notes []string
	}
	tests := []struct {
		name string
		args args
		want ResourceMeta
	}{
		{
			name: "ok",
			args: args{
				notes: []string{"a"},
			},
			want: ResourceMeta{
				name:     "notes",
				value:    []string{"a"},
				validErr: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewResourceMetaNotes(tt.args.notes...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewResourceMetaNotes() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResourceMetaCountries(t *testing.T) {
	type args struct {
		countries []string
	}
	tests := []struct {
		name string
		args args
		want ResourceMeta
	}{
		{
			name: "",
			args: args{
				countries: []string{"a"},
			},
			want: ResourceMeta{
				name:     "countries",
				value:    []string{"a"},
				validErr: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewResourceMetaCountries(tt.args.countries...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewResourceMetaCountries() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResourceMetaContinents(t *testing.T) {
	type args struct {
		continents []string
	}
	tests := []struct {
		name string
		args args
		want ResourceMeta
	}{
		{
			name: "ok",
			args: args{
				continents: []string{"a"},
			},
			want: ResourceMeta{
				name:     "continents",
				value:    []string{"a"},
				validErr: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewResourceMetaContinents(tt.args.continents...); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewResourceMetaContinents() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResourceMetaDefault(t *testing.T) {
	tests := []struct {
		name string
		want ResourceMeta
	}{
		{
			name: "ok",
			want: ResourceMeta{
				name:     "default",
				value:    true,
				validErr: nil,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewResourceMetaDefault(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewResourceMetaDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewResourceMetaCidrLabels(t *testing.T) {
	type args struct {
		cidrLabels map[string]int
	}
	tests := []struct {
		name string
		args args
		want ResourceMeta
	}{
		{
			name: "ok",
			args: args{
				cidrLabels: map[string]int{"label1": 1, "label2": 2},
			},
			want: ResourceMeta{
				name:     "cidr_labels",
				value:    map[string]int{"label1": 1, "label2": 2},
				validErr: nil,
			},
		},
		{
			name: "empty map",
			args: args{
				cidrLabels: map[string]int{},
			},
			want: ResourceMeta{
				validErr: fmt.Errorf("cidrLabels is empty"),
			},
		},
		{
			name: "nil map",
			args: args{
				cidrLabels: nil,
			},
			want: ResourceMeta{
				validErr: fmt.Errorf("cidrLabels is empty"),
			},
		},
		{
			name: "empty key",
			args: args{
				cidrLabels: map[string]int{"": 1},
			},
			want: ResourceMeta{
				validErr: fmt.Errorf("cidrLabels key or value is empty"),
			},
		},
		{
			name: "negative value",
			args: args{
				cidrLabels: map[string]int{"label1": -1},
			},
			want: ResourceMeta{
				validErr: fmt.Errorf("cidrLabels key or value is empty"),
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewResourceMetaCidrLabels(tt.args.cidrLabels); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("NewResourceMetaCidrLabels() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestResourceRecords_AddMeta(t *testing.T) {
	type fields struct {
		Content []any
		Meta    map[string]any
	}
	type args struct {
		meta ResourceMeta
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   ResourceRecord
	}{
		{
			name: "",
			fields: fields{
				Meta: nil,
			},
			args: args{
				meta: ResourceMeta{
					name:  "a",
					value: 1,
				},
			},
			want: ResourceRecord{
				Meta: map[string]any{"a": 1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ResourceRecord{
				Content: tt.fields.Content,
				Meta:    tt.fields.Meta,
			}
			if got := r.AddMeta(tt.args.meta); !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("AddMeta() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHttpsSvcbParams(t *testing.T) {
	r := ResourceRecord{
		Content: []any{
			[]any{"alpn", "h3", "h2"},
			[]any{"no-default-alpn"},
			[]any{"ipv4hint", "127.0.0.1", "10.0.0.1"},
			[]any{"port", 1234},
		},
	}
	str := r.ContentToString()
	assert.Equal(t, `alpn="h3,h2" no-default-alpn ipv4hint=127.0.0.1,10.0.0.1 port=1234`, str)
}

func TestIPNet_MarshalUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		cidr      string
		expectErr bool
	}{
		{
			name:      "valid IPv4 CIDR",
			cidr:      "192.168.1.0/24",
			expectErr: false,
		},
		{
			name:      "valid IPv6 CIDR",
			cidr:      "2001:db8::/32",
			expectErr: false,
		},
		{
			name:      "invalid CIDR",
			cidr:      "not-a-cidr",
			expectErr: true,
		},
		{
			name:      "empty string",
			cidr:      "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test Unmarshal
			jsonInput := []byte(fmt.Sprintf(`"%s"`, tt.cidr))
			var ipn IPNet
			err := ipn.UnmarshalJSON(jsonInput)

			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.cidr, ipn.String())

				// Test Marshal
				marshaled, err := ipn.MarshalJSON()
				assert.NoError(t, err)
				assert.Equal(t, jsonInput, marshaled)
			}
		})
	}

	// Test unmarshaling invalid JSON
	t.Run("invalid json", func(t *testing.T) {
		var ipn IPNet
		err := ipn.UnmarshalJSON([]byte(`not-json`))
		assert.Error(t, err)
	})

	// Test marshaling zero value
	t.Run("marshal zero value", func(t *testing.T) {
		var ipn IPNet
		marshaled, err := ipn.MarshalJSON()
		assert.NoError(t, err)
		assert.Equal(t, []byte(`""`), marshaled)
	})
}
