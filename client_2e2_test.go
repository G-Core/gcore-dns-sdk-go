package dnssdk

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewClient(t *testing.T) {
	apiToken := strings.TrimSpace(os.Getenv("TESTS_API_PERMANENT_TOKEN"))
	if apiToken == "" {
		t.Skip("no defined TESTS_API_PERMANENT_TOKEN")
	}

	sdk := NewClient(PermanentAPIKeyAuth(apiToken), func(client *Client) {
		client.Debug = true
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	sold := time.Now().Unix()

	// create zone

	zoneName := fmt.Sprintf("testzone%d.sdk", sold)
	_, err := sdk.CreateZone(ctx, zoneName)
	if err != nil {
		t.Fatal("create zone", err)
	}

	// read zone

	zoneResp, err := sdk.Zone(ctx, zoneName)
	if err != nil {
		t.Fatal("read zone", err)
	}
	if !strings.Contains(zoneResp.Name, zoneName) {
		t.Fatalf("read zone want %s got %s", zoneName, zoneResp.Name)
	}

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
		30,
		WithFilters(NewDefaultFilter(1, true)))
	if err != nil {
		t.Fatal("add rrSet", err)
	}

	err = sdk.AddZoneRRSet(ctx,
		zoneName,
		recName,
		recTypeSecond,
		[]ResourceRecord{
			*(&ResourceRecord{}).SetContent(recTypeSecond, recValSecond),
		},
		30,
		WithFilters(NewDefaultFilter(1, true)))
	if err != nil {
		t.Fatal("add rrSet", err)
	}

	// update rrSet

	recVal2 := "second"
	err = sdk.UpdateRRSet(ctx,
		zoneName,
		recName,
		recType,
		RRSet{
			TTL: 60,
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
	if err != nil {
		t.Fatal("update rrSet", err)
	}

	// read zone with records

	zonesResp, err := sdk.ZonesWithRecords(ctx, func(f *ZonesFilter) {
		f.Names = []string{zoneName}
	})
	if err != nil {
		t.Fatal("read zone with record", err)
	}
	if len(zonesResp) != 1 {
		t.Fatalf("read zone with records: wrong len: got %d", len(zonesResp))
	}
	wantZone := Zone{
		Name: zoneName,
		Records: []ZoneRecord{
			{
				Name:         recName,
				Type:         recType,
				TTL:          60,
				ShortAnswers: []string{recVal, recVal2},
			},
		},
	}
	if zonesResp[0].Name != wantZone.Name {
		t.Fatalf("read zone with records: wrong name: got= %s , want= %s", zonesResp[0].Name, wantZone.Name)
	}
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

	// delete rrSet content

	err = sdk.DeleteRRSetRecord(ctx, zoneName, recName, recType, recVal2)

	if err != nil {
		t.Fatal("delete rrSet content", err)
	}

	// read rrSet

	rrSet, err := sdk.RRSet(ctx, zoneName, recName, recType)
	if err != nil {
		t.Fatal("read rrSet", err)
	}
	wantRrSet := RRSet{
		TTL: 60,
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
	if rrSet.TTL != wantRrSet.TTL {
		t.Fatalf("read rrSet ttl: wrong res: got= %+v , want= %+v",
			rrSet.TTL, wantRrSet.TTL)
	}
	if !reflect.DeepEqual(rrSet.Records[0].Content, wantRrSet.Records[0].Content) {
		t.Fatalf("read rrSet content: wrong res: got= %+v , want= %+v",
			rrSet.Records[0].Content, wantRrSet.Records[0].Content)
	}
	if !reflect.DeepEqual(rrSet.Filters, wantRrSet.Filters) {
		t.Fatalf("read rrSet filters: wrong res: got= %+v , want= %+v",
			rrSet.Filters, wantRrSet.Filters)
	}
	if fmt.Sprint(rrSet.Records[0].Meta["asn"]) != fmt.Sprint(wantRrSet.Records[0].Meta["asn"]) {
		t.Fatalf("read rrSet meta asn: wrong res: got= %+v %T, want= %+v %T",
			rrSet.Records[0].Meta["asn"], rrSet.Records[0].Meta["asn"],
			wantRrSet.Records[0].Meta["asn"], wantRrSet.Records[0].Meta["asn"])
	}
	if fmt.Sprint(rrSet.Records[0].Meta["default"]) != fmt.Sprint(wantRrSet.Records[0].Meta["default"]) {
		t.Fatalf("read rrSet meta default: wrong res: got= %+v %T, want= %+v",
			rrSet.Records[0].Meta["default"], rrSet.Records[0].Meta["default"], wantRrSet.Records[0].Meta["default"])
	}
	if fmt.Sprint(rrSet.Records[0].Meta["latlong"]) != fmt.Sprint(wantRrSet.Records[0].Meta["latlong"]) {
		t.Fatalf("read rrSet meta latlong: wrong res: got= %+v %T , want= %+v",
			rrSet.Records[0].Meta["latlong"], rrSet.Records[0].Meta["latlong"], wantRrSet.Records[0].Meta["latlong"])
	}

	// delete rrSet

	err = sdk.DeleteRRSet(ctx, zoneName, recName, recType)

	if err != nil {
		t.Fatal("delete rrSet", err)
	}

	// delete zone

	err = sdk.DeleteZone(ctx, zoneName)

	if err != nil {
		t.Fatal("delete zone", err)
	}
}
