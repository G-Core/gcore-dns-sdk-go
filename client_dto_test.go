package dnssdk

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"
)

func TestRecordTypeMX_ToContent(t *testing.T) {
	tests := []struct {
		name string
		mx   RecordTypeMX
		want []string
	}{
		{
			name: "ok",
			mx:   "10 mail.server",
			want: []string{"10", "mail.server"},
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
		want []string
	}{
		{
			name: "ok",
			caa:  "10 issue aaa",
			want: []string{"10", "issue", "aaa"},
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

func TestRecordTypeAny_ToContent(t *testing.T) {
	tests := []struct {
		name string
		any  RecordTypeAny
		want []string
	}{
		{
			name: "ok",
			any:  "any any 34",
			want: []string{"any any 34"},
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
		want []string
	}{
		{
			name: "mx",
			args: args{
				recordType: "MX",
				content:    "10 mx.com",
			},
			want: []string{"10", "mx.com"},
		},
		{
			name: "caa",
			args: args{
				recordType: "CAA",
				content:    "10 issue com",
			},
			want: []string{"10", "issue", "com"},
		},
		{
			name: "any",
			args: args{
				recordType: "A",
				content:    "10 issue com",
			},
			want: []string{"10 issue com"},
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

func TestResourceRecords_AddMeta(t *testing.T) {
	type fields struct {
		Content []string
		Meta    map[string]interface{}
	}
	type args struct {
		meta ResourceMeta
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   ResourceRecords
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
			want: ResourceRecords{
				Meta: map[string]interface{}{"a": 1},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &ResourceRecords{
				Content: tt.fields.Content,
				Meta:    tt.fields.Meta,
			}
			if got := r.AddMeta(tt.args.meta); !reflect.DeepEqual(*got, tt.want) {
				t.Errorf("AddMeta() = %v, want %v", got, tt.want)
			}
		})
	}
}
