package dnssdk

import (
	"context"
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// defaultTTL - users who are on the FREE plan have the limitation of setting the time-to-live (ttl)
// to a minimum of three minutes.
const defaultTTL = 120

var defaultNS = []string{"ns1.gcorelabs.net", "ns2.gcdn.services"}

func TestE2E_ZonesWithRRSets(t *testing.T) {
	apiToken := strings.TrimSpace(os.Getenv("TESTS_API_PERMANENT_TOKEN"))
	if apiToken == "" {
		t.Skip("no defined TESTS_API_PERMANENT_TOKEN")
	}

	sdk := NewClient(PermanentAPIKeyAuth(apiToken), func(client *Client) {
		client.Debug = true
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	zoneName := fmt.Sprintf("testzone.%s.sdk.com", randStr())
	_, err := sdk.CreateZone(ctx, zoneName, AddZone{Name: zoneName})
	require.NoError(t, err, "create zone")

	// read zone
	zoneResp, err := sdk.Zone(ctx, zoneName)
	require.NoError(t, err, "read zone")
	require.Contains(t, zoneResp.Name, zoneName, "read zone")

	// add rrSet
	recName := "www." + zoneName
	recType := "TXT"
	recVal := "12345"

	recTypeSecond := "MX"
	recValSecond := "10 my.mail.server.com"

	err = sdk.AddZoneRRSet(ctx,
		zoneName,
		recName,
		recType,
		[]ResourceRecord{
			*(&ResourceRecord{}).
				SetContent(recType, recVal).
				AddMeta(NewResourceMetaLatLong("3.3,4.4")),
		},
		defaultTTL,
		defaultFilterOpts())

	require.NoError(t, err, "add rrSet")

	err = sdk.AddZoneRRSet(ctx,
		zoneName,
		recName,
		recTypeSecond,
		[]ResourceRecord{
			*(&ResourceRecord{}).SetContent(recTypeSecond, recValSecond),
		},
		defaultTTL,
		defaultFilterOpts())

	require.NoError(t, err, "add rrSet")

	recVal2 := "second"
	err = sdk.UpdateRRSet(ctx,
		zoneName,
		recName,
		recType,
		RRSet{
			TTL: 180,
			Records: []ResourceRecord{
				*(&ResourceRecord{Enabled: true}).
					SetContent(recType, recVal).
					AddMeta(NewResourceMetaLatLong("1.1,2.2")).
					AddMeta(NewResourceMetaDefault()).
					AddMeta(NewResourceMetaAsn(1)),
				*(&ResourceRecord{}).
					SetContent(recType, recVal2).
					AddMeta(NewResourceMetaNotes("note")),
			},
			Filters: []RecordFilter{NewGeoDNSFilter(1, true)},
		},
	)
	require.NoError(t, err)

	zonesResp, err := sdk.ZonesWithRecords(ctx, func(f *ZonesFilter) {
		f.Names = []string{zoneName}
	})
	require.NoError(t, err, "read zone with records")
	require.Len(t, zonesResp, 1, "read zone with records")

	wantZone := Zone{
		Name: zoneName,
		Records: []ZoneRecord{
			{
				Name:         recName,
				Type:         recType,
				TTL:          180,
				ShortAnswers: []string{recVal, recVal2},
			},
		},
	}
	require.Equal(t, wantZone.Name, zonesResp[0].Name, "read zone with records")

	recChecked := false
	for _, rec := range zonesResp[0].Records {
		if rec.Type != recType {
			continue
		}
		recChecked = true
		if !reflect.DeepEqual(rec, wantZone.Records[0]) {
			t.Fatalf("read zone with records: wrong records: got= %+v , want= %+v", rec, wantZone.Records[0])
		}
		break
	}
	if !recChecked {
		t.Fatalf("read zone with records: wrong records: got= %+v , want= %+v",
			zonesResp[0].Records, wantZone.Records)
	}

	ns, err := sdk.ZoneNameservers(ctx, zoneName)
	if err != nil {
		t.Fatal("read zone nameservers", err)
	}

	assert.ElementsMatch(t, ns, defaultNS, "read zone nameservers")

	err = sdk.DeleteRRSetRecord(ctx, zoneName, recName, recType, recVal2)
	require.NoError(t, err, "delete rrSet record")

	rrSet, err := sdk.RRSet(ctx, zoneName, recName, recType, 0, 0)
	require.NoError(t, err, "read rrSet")

	wantRrSet := RRSet{
		TTL: 180,
		Records: []ResourceRecord{
			{
				Content: []interface{}{recVal},
				Meta: map[string]interface{}{
					"latlong": []interface{}{1.1, 2.2},
					"default": true,
					"asn":     []interface{}{1},
				},
				Enabled: true,
			},
		},
		Filters: []RecordFilter{NewGeoDNSFilter(1, true)},
	}

	wantRecord := wantRrSet.Records[0]
	gotRecord := rrSet.Records[0]

	assert.Equal(t, rrSet.TTL, wantRrSet.TTL, "ttl")
	assert.Equal(t, rrSet.Filters, wantRrSet.Filters, "filters")
	assert.Equal(t, gotRecord.Content, wantRecord.Content, "content")
	assert.Equal(t, gotRecord.Meta["default"], wantRecord.Meta["default"], "meta default")
	assert.Equal(t, gotRecord.Meta["latlong"], wantRecord.Meta["latlong"], "meta latlong")
	assert.Equal(t, fmt.Sprint(gotRecord.Meta["asn"]), fmt.Sprint(wantRecord.Meta["asn"]), "meta asn")

	err = sdk.DeleteRRSet(ctx, zoneName, recName, recType)
	require.NoError(t, err, "delete rrSet")

	err = sdk.DeleteZone(ctx, zoneName)
	require.NoError(t, err, "delete zone")
}

func TestClientE2E_ZoneNameservers(t *testing.T) {
	apiToken := strings.TrimSpace(os.Getenv("TESTS_API_PERMANENT_TOKEN"))
	if apiToken == "" {
		t.Skip("no defined TESTS_API_PERMANENT_TOKEN")
	}

	sdk := NewClient(PermanentAPIKeyAuth(apiToken), func(client *Client) {
		client.Debug = true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	zoneName := fmt.Sprintf("testzone.%s.sdk.com", randStr())
	_, err := sdk.CreateZone(ctx, zoneName, AddZone{Name: zoneName})
	require.NoError(t, err, "create zone")

	defer func() {
		err = sdk.DeleteZone(ctx, zoneName)
		require.NoError(t, err, "cleanup zone")
	}()

	expZones := []string{
		"ns3.gcdn.services", "ns4.gcdn.services", "ns5.gcdn.services", "ns6.gcdn.services",
		"ns7.gcdn.services", "ns8.gcdn.services", "ns9.gcdn.services", "ns10.gcdn.services",
		"ns11.gcdn.services", "ns12.gcdn.services", "ns13.gcdn.services", "ns14.gcdn.services",
		"ns15.gcdn.services", "ns16.gcdn.services", "ns17.gcdn.services", "ns18.gcdn.services",
		"ns19.gcdn.services", "ns20.gcdn.services", "ns21.gcdn.services", "ns22.gcdn.services",
	}

	group, ctxGroup := errgroup.WithContext(ctx)

	for _, z := range expZones {
		zone := z
		group.Go(func() error {
			rr := ResourceRecord{}
			rr.SetContent(nsRecordType, zone)

			return sdk.AddZoneRRSet(ctxGroup, zoneName, randStr()+"."+zoneName, nsRecordType, []ResourceRecord{rr},
				defaultTTL, defaultFilterOpts())
		})
	}

	group.Go(func() error {
		rr := ResourceRecord{}
		rr.SetContent("TXT", "12345")
		rr.AddMeta(NewResourceMetaLatLong("3.3,4.4"))

		return sdk.AddZoneRRSet(ctxGroup, zoneName, "www."+zoneName, "TXT", []ResourceRecord{rr},
			defaultTTL, defaultFilterOpts())
	})

	group.Go(func() error {
		rr := ResourceRecord{}
		rr.SetContent("MX", "10 my.mail.server.com")

		return sdk.AddZoneRRSet(ctxGroup, zoneName, "www."+zoneName, "MX", []ResourceRecord{rr},
			defaultTTL, defaultFilterOpts())
	})

	err = group.Wait()
	require.NoError(t, err, "add zone rrSets")

	ns, err := sdk.ZoneNameservers(ctx, zoneName)
	if err != nil {
		t.Fatal("read zone nameservers", err)
	}

	expNS := append(expZones, defaultNS...)
	assert.ElementsMatch(t, ns, expNS)
}

func TestClientE2E_ZoneWithDNSSEC(t *testing.T) {
	apiToken := strings.TrimSpace(os.Getenv("TESTS_API_PERMANENT_TOKEN"))
	if apiToken == "" {
		t.Skip("no defined TESTS_API_PERMANENT_TOKEN")
	}

	sdk := NewClient(PermanentAPIKeyAuth(apiToken), func(client *Client) {
		client.Debug = true
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	zoneName := fmt.Sprintf("dnssec.testzone.%s.sdk.com", randStr())
	_, err := sdk.CreateZone(ctx, zoneName, AddZone{Name: zoneName})
	require.NoError(t, err, "create zone")

	defer func() {
		err = sdk.DeleteZone(ctx, zoneName)
		require.NoError(t, err, "cleanup zone")
	}()

	_, err = sdk.Zone(ctx, zoneName)
	require.NoError(t, err, "read zone")

	rr := ResourceRecord{}
	rr.SetContent("HTTPS", "1 . ipv4hint=1.2.3.4,5.6.7.8")

	err = sdk.AddZoneRRSet(ctx, zoneName, "www."+zoneName, "HTTPS", []ResourceRecord{rr},
		defaultTTL, defaultFilterOpts())

	dnsSecDS, err := sdk.DNSSecDS(ctx, zoneName)
	require.EqualError(t, err, "get dnssec: 400: dnssec is disabled")
	assert.Empty(t, dnsSecDS)

	dnsSecDS, err = sdk.ToggleDnssec(ctx, zoneName, true)
	require.NoError(t, err, "add zone dnssec")
	assert.NotEmpty(t, dnsSecDS)

	dnsSecDS, err = sdk.DNSSecDS(ctx, zoneName)
	require.NoError(t, err)
	assert.NotEmpty(t, dnsSecDS)

	// It is not possible to test the DNSSEC disabling because it may take some time to be disabled.
}

func defaultFilterOpts() AddZoneOpt {
	return WithFilters(NewDefaultFilter(1, true))
}

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyz")

func randStr() string {
	b := make([]rune, 10)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return string(b)
}
