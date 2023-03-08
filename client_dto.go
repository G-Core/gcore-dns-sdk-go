package dnssdk

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ListZones dto to read list of zones from API
type ListZones struct {
	Zones []Zone `json:"zones"`
}

// Zone dto to read info from API
type Zone struct {
	Name    string       `json:"name"`
	Records []ZoneRecord `json:"records"`
}

// AddZone dto to create new zone
type AddZone struct {
	Name string `json:"name"`
}

// CreateResponse dto to create new zone
type CreateResponse struct {
	ID    uint64 `json:"id,omitempty"`
	Error string `json:"error,omitempty"`
}

// RRSet dto as part of zone info from API
type RRSet struct {
	Type    string           `json:"type"`
	TTL     int              `json:"ttl"`
	Records []ResourceRecord `json:"resource_records"`
	Filters []RecordFilter   `json:"filters"`
}

type RRSets struct {
	RRSets []RRSet `json:"rrsets"`
}

// ResourceRecord dto describe records in RRSet
type ResourceRecord struct {
	Content []interface{}          `json:"content"`
	Meta    map[string]interface{} `json:"meta"`
	Enabled bool                   `json:"enabled"`
}

// ContentToString as short value
func (r ResourceRecord) ContentToString() string {
	parts := make([]string, len(r.Content))
	for i := range r.Content {
		parts[i] = fmt.Sprint(r.Content[i])
	}
	return strings.Join(parts, " ")
}

// RecordFilter describe Filters in RRSet
type RecordFilter struct {
	Limit  uint   `json:"limit"`
	Type   string `json:"type"`
	Strict bool   `json:"strict"`
}

// NewGeoDNSFilter for RRSet
func NewGeoDNSFilter(limit uint, strict bool) RecordFilter {
	return RecordFilter{
		Limit:  limit,
		Type:   "geodns",
		Strict: strict,
	}
}

// NewGeoDistanceFilter for RRSet
func NewGeoDistanceFilter(limit uint, strict bool) RecordFilter {
	return RecordFilter{
		Limit:  limit,
		Type:   "geodistance",
		Strict: strict,
	}
}

// NewDefaultFilter for RRSet
func NewDefaultFilter(limit uint, strict bool) RecordFilter {
	return RecordFilter{
		Limit:  limit,
		Type:   "default",
		Strict: strict,
	}
}

// NewFirstNFilter for RRSet
func NewFirstNFilter(limit uint, strict bool) RecordFilter {
	return RecordFilter{
		Limit:  limit,
		Type:   "first_n",
		Strict: strict,
	}
}

// RecordType contract
type RecordType interface {
	ToContent() []interface{}
}

// RecordTypeMX as type of record
type RecordTypeMX string

// ToContent convertor
func (mx RecordTypeMX) ToContent() []interface{} {
	parts := strings.Split(string(mx), " ")
	// nolint: gomnd
	if len(parts) != 2 {
		return nil
	}
	content := make([]interface{}, len(parts))
	// nolint: gomnd
	content[1] = parts[1]
	// nolint: gomnd
	content[0], _ = strconv.ParseInt(parts[0], 10, 64)

	return content
}

// RecordTypeCAA as type of record
type RecordTypeCAA string

// ToContent convertor
func (caa RecordTypeCAA) ToContent() []interface{} {
	parts := strings.Split(string(caa), " ")
	// nolint: gomnd
	if len(parts) < 3 {
		return nil
	}
	content := make([]interface{}, len(parts))
	// nolint: gomnd
	content[1] = parts[1]
	// nolint: gomnd
	content[2] = strings.Join(parts[2:], " ")
	// nolint: gomnd
	content[0], _ = strconv.ParseInt(parts[0], 10, 64)

	return content
}

// RecordTypeSRV as type of record
type RecordTypeSRV string

// ToContent convertor
func (srv RecordTypeSRV) ToContent() []interface{} {
	parts := strings.Split(string(srv), " ")
	// nolint: gomnd
	if len(parts) != 4 {
		return nil
	}
	content := make([]interface{}, len(parts))
	// nolint: gomnd
	content[0], _ = strconv.ParseInt(parts[0], 10, 64)
	// nolint: gomnd
	content[1], _ = strconv.ParseInt(parts[1], 10, 64)
	// nolint: gomnd
	content[2], _ = strconv.ParseInt(parts[2], 10, 64)
	// nolint: gomnd
	content[3] = parts[3]

	return content
}

// RecordTypeAny as type of record
type RecordTypeAny string

// ToContent convertor
func (any RecordTypeAny) ToContent() []interface{} {
	return []interface{}{string(any)}
}

// ToRecordType builder
func ToRecordType(rType, content string) RecordType {
	switch strings.ToLower(rType) {
	case "mx":
		return RecordTypeMX(content)
	case "caa":
		return RecordTypeCAA(content)
	case "srv":
		return RecordTypeSRV(content)
	}
	return RecordTypeAny(content)
}

// ContentFromValue convertor from flat value to valid for api
func ContentFromValue(recordType, content string) []interface{} {
	rt := ToRecordType(recordType, content)
	if rt == nil {
		return nil
	}
	return rt.ToContent()
}

// ResourceMeta for ResourceRecord
type ResourceMeta struct {
	name     string
	value    interface{}
	validErr error
}

// Valid error
func (rm ResourceMeta) Valid() error {
	return rm.validErr
}

// NewResourceMetaIP for ip meta
func NewResourceMetaIP(ips ...string) ResourceMeta {
	for _, v := range ips {
		ip := net.ParseIP(v)
		if ip == nil {
			// nolint: goerr113
			return ResourceMeta{validErr: fmt.Errorf("wrong ip")}
		}
	}
	return ResourceMeta{
		name:  "ip",
		value: ips,
	}
}

// NewResourceMetaAsn for asn meta
func NewResourceMetaAsn(asn ...uint64) ResourceMeta {
	return ResourceMeta{
		name:  "asn",
		value: asn,
	}
}

// NewResourceMetaLatLong for lat long meta
func NewResourceMetaLatLong(latlong string) ResourceMeta {
	latlong = strings.TrimLeft(latlong, "(")
	latlong = strings.TrimLeft(latlong, "[")
	latlong = strings.TrimLeft(latlong, "{")
	latlong = strings.TrimRight(latlong, ")")
	latlong = strings.TrimRight(latlong, "]")
	latlong = strings.TrimRight(latlong, "}")
	parts := strings.Split(strings.ReplaceAll(latlong, " ", ""), ",")
	// nolint: gomnd
	if len(parts) != 2 {
		// nolint: goerr113
		return ResourceMeta{validErr: fmt.Errorf("latlong invalid format")}
	}
	lat, err := strconv.ParseFloat(parts[0], 64)
	if err != nil {
		// nolint: goerr113
		return ResourceMeta{validErr: fmt.Errorf("lat is invalid: %w", err)}
	}
	long, err := strconv.ParseFloat(parts[1], 64)
	// nolint: goerr113
	if err != nil {
		return ResourceMeta{validErr: fmt.Errorf("long is invalid: %w", err)}
	}

	return ResourceMeta{
		name:  "latlong",
		value: []float64{lat, long},
	}
}

// NewResourceMetaNotes for notes meta
func NewResourceMetaNotes(notes ...string) ResourceMeta {
	return ResourceMeta{
		name:  "notes",
		value: notes,
	}
}

// NewResourceMetaCountries for Countries meta
func NewResourceMetaCountries(countries ...string) ResourceMeta {
	return ResourceMeta{
		name:  "countries",
		value: countries,
	}
}

// NewResourceMetaContinents for continents meta
func NewResourceMetaContinents(continents ...string) ResourceMeta {
	return ResourceMeta{
		name:  "continents",
		value: continents,
	}
}

// NewResourceMetaDefault for default meta
func NewResourceMetaDefault() ResourceMeta {
	return ResourceMeta{
		name:  "default",
		value: true,
	}
}

// SetContent to ResourceRecord
func (r *ResourceRecord) SetContent(recordType, val string) *ResourceRecord {
	r.Content = ContentFromValue(recordType, val)
	return r
}

// AddMeta to ResourceRecord
func (r *ResourceRecord) AddMeta(meta ResourceMeta) *ResourceRecord {
	if meta.validErr != nil {
		return r
	}
	if meta.name == "" || meta.value == "" {
		return r
	}
	if r.Meta == nil {
		r.Meta = map[string]interface{}{}
	}
	r.Meta[meta.name] = meta.value
	return r
}

// AddFilter to RRSet
func (rr *RRSet) AddFilter(filters ...RecordFilter) *RRSet {
	if rr.Filters == nil {
		rr.Filters = make([]RecordFilter, 0)
	}
	rr.Filters = append(rr.Filters, filters...)
	return rr
}

// ZoneRecord dto describe records in Zone
type ZoneRecord struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"`
	TTL          uint     `json:"ttl"`
	ShortAnswers []string `json:"short_answers"`
}

// APIError customization for API calls
type APIError struct {
	StatusCode int    `json:"-"`
	Message    string `json:"error,omitempty"`
}

// Error implementation
func (a APIError) Error() string {
	return fmt.Sprintf("%d: %s", a.StatusCode, a.Message)
}
