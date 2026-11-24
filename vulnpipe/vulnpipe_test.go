package vulnpipe

import (
	"strings"
	"testing"
)

func TestValidateCandidate(t *testing.T) {
	ok := CandidateInput{Title: "订单查询参数 id 直接拼 SQL", Kind: KindSink, Location: "GET /api/order/detail?id=1"}
	if err := ValidateCandidate(ok); err != nil {
		t.Fatalf("合法候选被拒: %v", err)
	}
	cases := []struct {
		name string
		in   CandidateInput
		want string
	}{
		{"缺标题", CandidateInput{Location: "/x"}, "title"},
		{"缺位置", CandidateInput{Title: "可疑"}, "location"},
		{"标题过长", CandidateInput{Title: strings.Repeat("长", 201), Location: "/x"}, "过长"},
		{"跳缺 ref", CandidateInput{Title: "t", Location: "/x", Hops: []HopInput{{RefKind: HopTraffic}}}, "第 1 跳缺少 ref"},
	}
	for _, c := range cases {
		err := ValidateCandidate(c.in)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got %v, want 含 %q", c.name, err, c.want)
		}
	}
}

func TestNormalizeKindAndHop(t *testing.T) {
	for in, want := range map[string]string{
		" SINK ": KindSink, "Parse": KindParse, "logic": KindLogic, "auth": KindAuth,
		"config": KindConfig, "": KindOther, "whatever": KindOther,
	} {
		if got := NormalizeKind(in); got != want {
			t.Errorf("NormalizeKind(%q)=%q want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{
		"traffic": HopTraffic, "Source": HopSource, "command": HopCommand, "x": HopOther, "": HopOther,
	} {
		if got := NormalizeHopKind(in); got != want {
			t.Errorf("NormalizeHopKind(%q)=%q want %q", in, got, want)
		}
	}
}

func TestReachabilityStates(t *testing.T) {
	cases := []struct {
		name              string
		hops              []Hop
		status            string
		verified, unverif int
	}{
		{"没有路径", nil, ReachUnknown, 0, 0},
		{"全部核对", []Hop{{Verified: true}, {Verified: true}}, ReachVerified, 2, 0},
		{"部分核对", []Hop{{Verified: true}, {Verified: false}}, ReachPartial, 1, 1},
		{"一条没对上", []Hop{{Verified: false}, {Verified: false}}, ReachClaimed, 0, 2},
	}
	for _, c := range cases {
		status, v, u := Reachability(c.hops)
		if status != c.status || v != c.verified || u != c.unverif {
			t.Errorf("%s: got (%s,%d,%d) want (%s,%d,%d)", c.name, status, v, u, c.status, c.verified, c.unverif)
		}
	}
	if Label := ReachLabel(ReachVerified); !strings.Contains(Label, "已核实") {
		t.Errorf("ReachLabel(verified)=%q", Label)
	}
	if Label := ReachLabel(""); !strings.Contains(Label, "未知") {
		t.Errorf("空状态文案=%q", Label)
	}
}
