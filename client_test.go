package dnssdk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testToken          = "test"
	testRecordContent  = "acme"
	testRecordContent2 = "foo"
	txtRecordType      = "TXT"
	testTTL            = 10
)

func setupTest(t *testing.T) (*http.ServeMux, *Client) {
	t.Helper()

	mux := http.NewServeMux()

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := NewClient(PermanentAPIKeyAuth(testToken))
	client.BaseURL, _ = url.Parse(server.URL)

	return mux, client
}

func TestClient_Zone(t *testing.T) {
	mux, client := setupTest(t)

	expected := Zone{
		Name: "example.com",
		Records: []ZoneRecord{
			{
				Name:         "test.example.com",
				Type:         txtRecordType,
				TTL:          10,
				ShortAnswers: []string{"test1"},
			},
		},
	}

	mux.Handle("/v2/zones/example.com", validationHandler{
		method: http.MethodGet,
		next:   handleJSONResponse(expected),
	})

	zone, err := client.Zone(context.Background(), "example.com")
	require.NoError(t, err)

	assert.Equal(t, expected, zone)
}

func TestClient_CreateZone(t *testing.T) {
	mux, client := setupTest(t)

	expected := CreateResponse{
		ID: 1,
	}

	mux.Handle("/v2/zones", validationHandler{
		method: http.MethodPost,
		next:   handleJSONResponse(expected),
	})

	id, err := client.CreateZone(context.Background(), AddZone{Name: "example.com"})
	require.NoError(t, err)

	assert.Equal(t, expected.ID, id)
}

func TestClient_EnableZone(t *testing.T) {
	mux, client := setupTest(t)

	mux.Handle("/v2/zones/example.com/enable", validationHandler{
		method: http.MethodPatch,
	})

	err := client.EnableZone(context.Background(), "example.com")
	require.NoError(t, err)
}

func TestClient_DisableZone(t *testing.T) {
	mux, client := setupTest(t)

	mux.Handle("/v2/zones/example.com/disable", validationHandler{
		method: http.MethodPatch,
	})

	err := client.DisableZone(context.Background(), "example.com")
	require.NoError(t, err)
}

func TestClient_ImportZone(t *testing.T) {
	mux, client := setupTest(t)

	expected := ImportZoneResponse{
		Success: true,
	}

	importContent := "some bind file content"

	mux.Handle("/v2/zones/example.com/import", validationHandler{
		method: http.MethodPost,
		next: http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
			body := ImportZone{}
			err := json.NewDecoder(req.Body).Decode(&body)
			if err != nil {
				http.Error(rw, "failed to decode body", http.StatusBadRequest)
				return
			}
			if body.Content != importContent {
				http.Error(rw, "unexpected content", http.StatusBadRequest)
				return
			}

			handleJSONResponse(expected)(rw, req)
		}),
	})

	resp, err := client.ImportZone(context.Background(), "example.com", importContent)
	require.NoError(t, err)

	assert.Equal(t, expected, resp)
}

func TestClient_Zones(t *testing.T) {
	mux, client := setupTest(t)

	expected := []Zone{{Name: "example.com"}}

	mux.Handle("/v2/zones", validationHandler{
		method: http.MethodGet,
		next:   handleJSONResponse(ListZones{Zones: expected}),
	})

	zones, err := client.Zones(context.Background())
	require.NoError(t, err)

	assert.Equal(t, expected, zones)
}

func TestClient_ZonesWithRecords(t *testing.T) {
	mux, client := setupTest(t)

	expected := []Zone{
		{
			Name: "example.com",
			Records: []ZoneRecord{
				{
					Name:         "test.example.com",
					Type:         txtRecordType,
					TTL:          10,
					ShortAnswers: []string{"test1"},
				},
			},
		},
	}

	mux.Handle("/v2/zones", validationHandler{
		method: http.MethodGet,
		next:   handleJSONResponse(ListZones{Zones: []Zone{{Name: expected[0].Name}}}),
	})
	mux.Handle("/v2/zones/example.com", validationHandler{
		method: http.MethodGet,
		next:   handleJSONResponse(expected[0]),
	})

	zones, err := client.ZonesWithRecords(context.Background())
	require.NoError(t, err)

	assert.Equal(t, expected, zones)
}

func TestClient_Zone_error(t *testing.T) {
	mux, client := setupTest(t)

	mux.Handle("/v2/zones/example.com", validationHandler{
		method: http.MethodGet,
		next:   handleAPIError(),
	})

	_, err := client.Zone(context.Background(), "example.com")
	require.Error(t, err)
}

func TestClient_RRSet(t *testing.T) {
	mux, client := setupTest(t)

	expected := RRSet{
		TTL: testTTL,
		Filters: []RecordFilter{
			{
				Limit:  1,
				Type:   "geodns",
				Strict: false,
			},
		},
		Records: []ResourceRecord{
			{
				Content: []interface{}{testRecordContent},
				Meta:    map[string]interface{}{"notes": []interface{}{"note"}},
				Enabled: false,
			},
		},
	}

	mux.Handle("/v2/zones/example.com/foo.example.com/"+txtRecordType, validationHandler{
		method: http.MethodGet,
		next:   handleJSONResponse(expected),
	})

	rrSet, err := client.RRSet(context.Background(), "example.com", "foo.example.com", txtRecordType, 0, 0)
	require.NoError(t, err)

	assert.Equal(t, expected, rrSet)
}

func TestClient_RRSet_error(t *testing.T) {
	mux, client := setupTest(t)

	mux.Handle("/v2/zones/example.com/foo.example.com/"+txtRecordType, validationHandler{
		method: http.MethodGet,
		next:   handleAPIError(),
	})

	_, err := client.RRSet(context.Background(), "example.com", "foo.example.com", txtRecordType, 0, 0)
	require.Error(t, err)
}

func TestClient_DeleteRRSetRecord_Remove(t *testing.T) {
	mux, client := setupTest(t)
	rrSet := RRSet{
		TTL: 10,
		Records: []ResourceRecord{
			{
				Content: []interface{}{"1"},
			},
			{
				Content: []interface{}{"2"},
			},
			{
				Content: []interface{}{"3"},
			},
			{
				Content: []interface{}{"4"},
			},
		},
	}
	mux.HandleFunc("/v2/zones/test.example.com/foo.test.example.com/"+txtRecordType,
		func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				handleJSONResponse(rrSet)(writer, request)
			case http.MethodDelete:
			default:
				http.Error(writer, "wrong method", http.StatusNotFound)
			}
		})

	err := client.DeleteRRSetRecord(context.Background(),
		"test.example.com", "foo.test.example.com", txtRecordType, "1", "2", "3", "4")
	require.NoError(t, err)
}

func TestClient_DeleteRRSetRecord_Update(t *testing.T) {
	mux, client := setupTest(t)
	rrSet := RRSet{
		TTL: 10,
		Records: []ResourceRecord{
			{
				Content: []interface{}{"1"},
			},
			{
				Content: []interface{}{"2"},
			},
			{
				Content: []interface{}{"3"},
			},
			{
				Content: []interface{}{"4"},
			},
		},
	}
	mux.HandleFunc("/v2/zones/test.example.com/foo.test.example.com/"+txtRecordType,
		func(writer http.ResponseWriter, request *http.Request) {
			switch request.Method {
			case http.MethodGet:
				handleJSONResponse(rrSet).ServeHTTP(writer, request)
			case http.MethodPut:
				handleRRSet([]ResourceRecord{
					{
						Content: []interface{}{"1"},
					},
					{
						Content: []interface{}{"4"},
					},
				}).ServeHTTP(writer, request)
			default:
				http.Error(writer, "wrong method", http.StatusNotFound)
			}
		})

	err := client.DeleteRRSetRecord(context.Background(),
		"test.example.com", "foo.test.example.com.", txtRecordType, "2", "3")
	require.NoError(t, err)
}

func TestClient_DeleteRRSet(t *testing.T) {
	mux, client := setupTest(t)

	mux.Handle("/v2/zones/test.example.com/my.test.example.com/"+txtRecordType,
		validationHandler{method: http.MethodDelete})

	err := client.DeleteRRSet(context.Background(),
		"test.example.com", "my.test.example.com", txtRecordType)
	require.NoError(t, err)
}

func TestClient_DeleteRRSet_error(t *testing.T) {
	mux, client := setupTest(t)

	mux.Handle("/v2/zones/test.example.com/my.test.example.com/"+txtRecordType, validationHandler{
		method: http.MethodDelete,
		next:   handleAPIError(),
	})

	err := client.DeleteRRSet(context.Background(),
		"test.example.com", "my.test.example.com", txtRecordType)
	require.NotNil(t, err)
	require.Equal(t, err.Error(), "delete record request: 500: oops")
}

func TestClient_ZoneNameservers(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		zoneName string
		setUpMux func(mux *http.ServeMux)

		expRes []string
		expErr string
	}{
		{
			name:     "failed to get rrsets",
			zoneName: "example.com",
			setUpMux: func(mux *http.ServeMux) {
				mux.Handle("/v2/zones/example.com/rrsets", validationHandler{
					method: http.MethodGet,
					next:   handleAPIError(),
				})
			},
			expErr: "get rrsets example.com: 500: oops",
		},
		{
			name:     "empty response",
			zoneName: "example.com",
			setUpMux: func(mux *http.ServeMux) {
				mux.Handle("/v2/zones/example.com/rrsets", validationHandler{
					method: http.MethodGet,
					next:   handleJSONResponse(RRSets{}),
				})
			},
			expRes: []string{},
		},
		{
			name:     "nameservers",
			zoneName: "example.com",
			setUpMux: func(mux *http.ServeMux) {
				mux.Handle("/v2/zones/example.com/rrsets", validationHandler{
					method: http.MethodGet,
					next: handleJSONResponse(RRSets{
						RRSets: []RRSet{
							{Type: nsRecordType, Records: []ResourceRecord{{Content: []interface{}{"ns1.example.com."}}}},
							{Type: nsRecordType, Records: []ResourceRecord{{Content: []interface{}{"ns2.example.com.", "ns3.example.com."}}}},
						},
					}),
				})
			},
			expRes: []string{"ns1.example.com.", "ns2.example.com.", "ns3.example.com."},
		},
		{
			name:     "nameservers ignore duplicates",
			zoneName: "example.com",
			setUpMux: func(mux *http.ServeMux) {
				mux.Handle("/v2/zones/example.com/rrsets", validationHandler{
					method: http.MethodGet,
					next: handleJSONResponse(RRSets{
						RRSets: []RRSet{
							{Type: nsRecordType, Records: []ResourceRecord{{Content: []interface{}{"ns1.example.com."}}}},
							{Type: nsRecordType, Records: []ResourceRecord{{Content: []interface{}{"ns1.example.com."}}}},
						},
					}),
				})
			},
			expRes: []string{"ns1.example.com."},
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			mux, client := setupTest(t)
			tc.setUpMux(mux)

			res, err := client.ZoneNameservers(context.Background(), tc.zoneName)

			require.Equal(t, tc.expRes, res)
			if tc.expErr != "" {
				require.EqualError(t, err, tc.expErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClient_AddRRSet(t *testing.T) {
	testCases := []struct {
		desc          string
		zone          string
		recordName    string
		value         string
		handledDomain string
		handlers      map[string]http.Handler
		wantErr       bool
	}{
		{
			desc:       "success add",
			zone:       "test.example.com",
			recordName: "my.test.example.com",
			value:      testRecordContent,
			handlers: map[string]http.Handler{
				// createRRSet
				"/v2/zones/test.example.com/my.test.example.com/" + txtRecordType: validationHandler{
					method: http.MethodPost,
					next:   handleRRSet([]ResourceRecord{{Content: []interface{}{testRecordContent}}}),
				},
			},
		},
		{
			desc:       "success update",
			zone:       "test.example.com",
			recordName: "my.test.example.com",
			value:      testRecordContent,
			handlers: map[string]http.Handler{
				"/v2/zones/test.example.com/my.test.example.com/" + txtRecordType: http.HandlerFunc(
					func(rw http.ResponseWriter, req *http.Request) {
						switch req.Method {
						case http.MethodGet: // GetRRSet
							data := RRSet{
								TTL:     testTTL,
								Records: []ResourceRecord{{Content: []interface{}{testRecordContent2}}},
							}
							handleJSONResponse(data).ServeHTTP(rw, req)
						case http.MethodPut: // updateRRSet
							expected := []ResourceRecord{
								{Content: []interface{}{testRecordContent}},
								{Content: []interface{}{testRecordContent2}},
							}
							handleRRSet(expected).ServeHTTP(rw, req)
						default:
							http.Error(rw, "wrong method", http.StatusMethodNotAllowed)
						}
					}),
			},
		},
		{
			desc:       "not in the zone",
			zone:       "test.example.com",
			recordName: "notfound.example.com",
			value:      testRecordContent,
			wantErr:    true,
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			mux, cl := setupTest(t)

			for pattern, handler := range test.handlers {
				mux.Handle(pattern, handler)
			}

			err := cl.AddZoneRRSet(context.Background(),
				test.zone, test.recordName, txtRecordType, []ResourceRecord{{Content: []interface{}{test.value}}}, testTTL)
			if test.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

type validationHandler struct {
	method string
	next   http.Handler
}

func (v validationHandler) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.Header.Get("Authorization") != fmt.Sprintf("%s %s", tokenHeader, testToken) {
		rw.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(rw).Encode(APIError{Message: "authHeader up for parsing was not passed through the context"})
		return
	}

	if req.Method != v.method {
		http.Error(rw, "wrong method", http.StatusMethodNotAllowed)
		return
	}

	if v.next != nil {
		v.next.ServeHTTP(rw, req)
	}
}

func handleAPIError() http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(rw).Encode(APIError{Message: "oops"})
	}
}

func handleJSONResponse(data interface{}) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		err := json.NewEncoder(rw).Encode(data)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
	}
}

func handleRRSet(expected []ResourceRecord) http.HandlerFunc {
	return func(rw http.ResponseWriter, req *http.Request) {
		body := RRSet{}

		err := json.NewDecoder(req.Body).Decode(&body)
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}

		if body.TTL != testTTL {
			http.Error(rw, "wrong ttl", http.StatusInternalServerError)
			return
		}
		if !reflect.DeepEqual(body.Records, expected) {
			http.Error(rw, "wrong resource records", http.StatusInternalServerError)
		}
	}
}
