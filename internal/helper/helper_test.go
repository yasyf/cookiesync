package helper

import (
	"encoding/base64"
	"reflect"
	"strings"
	"testing"
)

func TestParseBatchLines(t *testing.T) {
	secret := []byte{0x00, 0xFF, 'a', '\t', '\n'}
	b64 := base64.StdEncoding.EncodeToString(secret)
	tests := []struct {
		name    string
		stdout  string
		want    []BatchLine
		wantErr string
	}{
		{
			name:   "ok line decodes the base64 secret",
			stdout: "0\tok\t" + b64 + "\n",
			want:   []BatchLine{{Index: 0, Status: BatchOK, Payload: secret}},
		},
		{
			name:   "missing line",
			stdout: "1\tmissing\t-\n",
			want:   []BatchLine{{Index: 1, Status: BatchMissing}},
		},
		{
			name:   "error line carries the OSStatus",
			stdout: "2\terror\t-25293\n",
			want:   []BatchLine{{Index: 2, Status: BatchError, OSStatus: -25293}},
		},
		{
			name:   "multiline batch keeps order and count",
			stdout: "0\tok\t" + b64 + "\n1\tmissing\t-\n2\terror\t-25308\n",
			want: []BatchLine{
				{Index: 0, Status: BatchOK, Payload: secret},
				{Index: 1, Status: BatchMissing},
				{Index: 2, Status: BatchError, OSStatus: -25308},
			},
		},
		{
			name:   "empty stdout is zero lines",
			stdout: "",
			want:   nil,
		},
		{
			name:    "two fields is malformed",
			stdout:  "0\tok\n",
			wantErr: "3 tab-separated fields",
		},
		{
			name:    "non-numeric index is malformed",
			stdout:  "x\tok\t" + b64 + "\n",
			wantErr: `index "x"`,
		},
		{
			name:    "bad base64 in an ok line is malformed",
			stdout:  "0\tok\t!!!\n",
			wantErr: `ok payload "!!!"`,
		},
		{
			name:    "unknown status is malformed",
			stdout:  "0\tdenied\t-\n",
			wantErr: `unknown status "denied"`,
		},
		{
			name:    "missing payload must be a dash",
			stdout:  "0\tmissing\tnope\n",
			wantErr: `want "-"`,
		},
		{
			name:    "error payload must be a decimal OSStatus",
			stdout:  "0\terror\tboom\n",
			wantErr: `error payload "boom"`,
		},
		{
			name:    "malformed second line names its index",
			stdout:  "0\tok\t" + b64 + "\ngarbage\n",
			wantErr: "batch line 1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseBatchLines(tt.stdout)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want it to contain %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseBatchLines: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("lines = %#v, want %#v", got, tt.want)
			}
		})
	}
}
