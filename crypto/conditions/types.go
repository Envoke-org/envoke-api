package conditions

import (
	"bytes"
	"crypto/sha256"
	"sort"
	"time"

	. "github.com/Envoke-org/envoke-api/common"
	"github.com/Envoke-org/envoke-api/crypto/crypto"
	"github.com/Envoke-org/envoke-api/crypto/ed25519"
	"github.com/Envoke-org/envoke-api/crypto/rsa"
)

func Sum256(p []byte) []byte {
	h := sha256.Sum256(p)
	return h[:]
}

// SHA256 Pre-Image

type fulfillmentPreImage struct {
	*fulfillment
}

func NewFulfillmentPreImage(preimage []byte, weight int) (*fulfillmentPreImage, error) {
	f := new(fulfillmentPreImage)
	f.fulfillment = NewFulfillment(PREIMAGE_ID, f, preimage, weight)
	if err := f.Init(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fulfillmentPreImage) Init() error {
	f.bitmask = PREIMAGE_BITMASK
	f.hash = Sum256(f.payload)
	f.size = len(f.payload)
	return nil
}

// SHA256 Prefix

type fulfillmentPrefix struct {
	*fulfillment
	prefix []byte
	sub    Fulfillment
}

func NewFulfillmentPrefix(prefix []byte, sub Fulfillment, weight int) (*fulfillmentPrefix, error) {
	if sub.IsCondition() {
		panic("Expected non-condition fulfillment")
	}
	f := new(fulfillmentPrefix)
	p, _ := sub.MarshalBinary()
	payload := append(VarOctet(prefix), p...)
	f.fulfillment = NewFulfillment(PREFIX_ID, f, payload, weight)
	f.prefix = prefix
	f.sub = sub
	if err := f.Init(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fulfillmentPrefix) Init() (err error) {
	if f.prefix == nil && f.sub == nil {
		buf := new(bytes.Buffer)
		buf.Write(f.payload)
		f.prefix = MustReadVarOctet(buf)
		f.sub, err = UnmarshalBinary(buf.Bytes(), f.weight)
		if err != nil {
			return err
		}
		if f.sub.IsCondition() {
			return Error("expected non-condition fulfillment")
		}
	}
	if f.prefix != nil && f.sub != nil {
		f.bitmask = PREFIX_BITMASK
		p, err := GetCondition(f.sub).MarshalBinary()
		if err != nil {
			return err
		}
		f.hash = Sum256(append(f.prefix, p...))
		f.size = len(f.payload)
		return nil
	}
	return Error("prefix and subfulfillment must both be set")
}

func (f *fulfillmentPrefix) Validate(p []byte) bool {
	if !f.fulfillment.Validate(nil) {
		return false
	}
	return f.sub.Validate(append(f.prefix, p...))
}

// ED25519

type fulfillmentEd25519 struct {
	*fulfillment
	pubkey *ed25519.PublicKey
	sig    *ed25519.Signature
}

func DefaultFulfillmentEd25519(pubkey *ed25519.PublicKey, sig *ed25519.Signature) (*fulfillmentEd25519, error) {
	return NewFulfillmentEd25519(pubkey, sig, 1)
}

func NewFulfillmentEd25519(pubkey *ed25519.PublicKey, sig *ed25519.Signature, weight int) (*fulfillmentEd25519, error) {
	f := new(fulfillmentEd25519)
	payload := append(pubkey.Bytes(), sig.Bytes()...)
	f.fulfillment = NewFulfillment(ED25519_ID, f, payload, weight)
	f.pubkey = pubkey
	f.sig = sig
	if err := f.Init(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fulfillmentEd25519) Details() Data {
	details := f.fulfillment.Details()
	details.Set("public_key", f.pubkey)
	details.Set("signature", nil)
	return details
}

func (f *fulfillmentEd25519) Init() error {
	if f.pubkey.Bytes() == nil {
		f.pubkey = new(ed25519.PublicKey)
		if err := f.pubkey.FromBytes(f.payload[:ed25519.PUBKEY_SIZE]); err != nil {
			return err
		}
	}
	if f.sig.Bytes() == nil {
		f.sig = new(ed25519.Signature)
		f.sig.FromBytes(f.payload[ed25519.PUBKEY_SIZE:])
	}
	f.bitmask = ED25519_BITMASK
	f.hash = f.pubkey.Bytes()
	f.size = ED25519_SIZE
	return nil
}

func (f *fulfillmentEd25519) PublicKey() crypto.PublicKey {
	if f.pubkey.Bytes() == nil {
		return nil
	}
	return f.pubkey
}

func (f *fulfillmentEd25519) Signature() crypto.Signature {
	if f.sig.Bytes() == nil {
		return nil
	}
	return f.sig
}

func (f *fulfillmentEd25519) Validate(p []byte) bool {
	if !f.fulfillment.Validate(nil) {
		return false
	}
	return f.pubkey.Verify(p, f.sig)
}

// SHA256 RSA

type fulfillmentRSA struct {
	*fulfillment
	pubkey *rsa.PublicKey
	sig    *rsa.Signature
}

func NewFulfillmentRSA(pubkey *rsa.PublicKey, sig *rsa.Signature, weight int) (*fulfillmentRSA, error) {
	f := new(fulfillmentRSA)
	payload := append(pubkey.Bytes(), sig.Bytes()...)
	f.fulfillment = NewFulfillment(RSA_ID, f, payload, weight)
	f.pubkey = pubkey
	f.sig = sig
	if err := f.Init(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fulfillmentRSA) Details() Data {
	details := f.fulfillment.Details()
	details.Set("public_key", f.pubkey)
	details.Set("signature", nil)
	return details
}

func (f *fulfillmentRSA) Init() error {
	if f.pubkey.Bytes() == nil {
		f.pubkey = new(rsa.PublicKey)
		if err := f.pubkey.FromBytes(f.payload[:rsa.KEY_SIZE]); err != nil {
			return err
		}
	}
	if f.sig.Bytes() == nil {
		f.sig = new(rsa.Signature)
		f.sig.FromBytes(f.payload[rsa.KEY_SIZE:])
	}
	f.bitmask = RSA_BITMASK
	f.hash = Sum256(f.pubkey.Bytes())
	f.size = RSA_SIZE
	return nil
}

func (f *fulfillmentRSA) PublicKey() crypto.PublicKey {
	if f.pubkey.Bytes() == nil {
		return nil
	}
	return f.pubkey
}

func (f *fulfillmentRSA) Signature() crypto.Signature {
	if f.sig.Bytes() == nil {
		return nil
	}
	return f.sig
}

func (f *fulfillmentRSA) Validate(p []byte) bool {
	if !f.fulfillment.Validate(nil) {
		return false
	}
	return f.pubkey.Verify(p, f.sig)
}

// SHA256 Threshold

type fulfillmentThreshold struct {
	*fulfillment
	subs      Fulfillments
	threshold int
}

func DefaultFulfillmentThreshold(subs Fulfillments) (*fulfillmentThreshold, error) {
	return NewFulfillmentThreshold(subs, len(subs), 1)
}

func NewFulfillmentThreshold(subs Fulfillments, threshold, weight int) (*fulfillmentThreshold, error) {
	if len(subs) == 0 {
		return nil, Error("must have more than 0 subs")
	}
	if threshold <= 0 {
		return nil, Error("threshold must be greater than 0")
	}
	sort.Sort(subs)
	payload := ThresholdPayload(subs, threshold)
	f := new(fulfillmentThreshold)
	f.fulfillment = NewFulfillment(THRESHOLD_ID, f, payload, weight)
	f.subs = subs
	f.threshold = threshold
	f.Init()
	return f, nil
}

func (f *fulfillmentThreshold) Init() error {
	if f.subs == nil && f.threshold == 0 {
		if err := f.ThresholdSubs(); err != nil {
			return err
		}
	}
	if f.subs == nil || f.threshold <= 0 {
		return Errorf("cannot have %d subs, threshold=%d", len(f.subs), f.threshold)
	}
	f.bitmask = ThresholdBitmask(f.subs)
	f.hash = ThresholdHash(f.subs, f.threshold)
	f.size = ThresholdSize(f.subs, f.threshold)
	return nil
}

func DefaultFulfillmentThresholdFromPubkeys(pubkeys []crypto.PublicKey) (*fulfillmentThreshold, error) {
	subs, err := DefaultFulfillmentsFromPubkeys(pubkeys)
	if err != nil {
		return nil, err
	}
	return NewFulfillmentThreshold(subs, len(pubkeys), 1)
}

func FulfillmentThresholdFromPubkeys(pubkeys []crypto.PublicKey, threshold, weight int, weights []int) (*fulfillmentThreshold, error) {
	subs, err := FulfillmentsFromPubkeys(pubkeys, weights)
	if err != nil {
		return nil, err
	}
	return NewFulfillmentThreshold(subs, threshold, weight)
}

// For testing..
func DefaultFulfillmentThresholdFromPrivkeys(msg []byte, privkeys ...crypto.PrivateKey) (_ *fulfillmentThreshold, err error) {
	n := len(privkeys)
	subs := make(Fulfillments, n)
	for i, privkey := range privkeys {
		subs[i], err = DefaultFulfillmentFromPrivkey(msg, privkey)
		if err != nil {
			return nil, err
		}
	}
	return NewFulfillmentThreshold(subs, n, 1)
}

func (f *fulfillmentThreshold) Details() Data {
	// TODO: validate
	subs := make([]Data, len(f.subs))
	for i, sub := range f.subs {
		subs[i] = sub.Details()
		subs[i].Set("weight", sub.Weight())
	}
	details := f.fulfillment.Details()
	details.Set("subfulfillments", subs)
	details.Set("threshold", f.threshold)
	return details
}

func ThresholdBitmask(subs Fulfillments) int {
	bitmask := THRESHOLD_BITMASK
	for _, sub := range subs {
		bitmask |= sub.Bitmask()
	}
	return bitmask
}

func ThresholdPayload(subs Fulfillments, threshold int) []byte {
	var i, j int
	numSubs := subs.Len()
	j = Exp2(numSubs)
	sums := make([]int, j)
	sets := make([]Fulfillments, j)
	thresholds := make([]int, j)
	for i, _ = range thresholds {
		thresholds[i] = threshold
	}
	for _, sub := range subs {
		j >>= 1
		with := true
		p, _ := GetCondition(sub).MarshalBinary()
		conditionLen := len(p)
		for i = range sums {
			if thresholds[i] > 0 {
				if with {
					sums[i] += sub.Size()
					sets[i] = append(sets[i], sub)
					thresholds[i] -= sub.Weight()
				} else if !with {
					sums[i] += conditionLen
				}
			}
			if (i+1)%j == 0 {
				with = !with
			}
		}
	}
	sum := 0
	var set Fulfillments
	for i = range sets {
		if thresholds[i] <= 0 {
			if sums[i] < sum || sum == 0 {
				set = sets[i]
				sum = sums[i]
			}
		}
	}
OUTER:
	for _, sub := range subs {
		for _, s := range set {
			if sub == s {
				continue OUTER
			}
		}
		sub.Init()
		set = append(set, GetCondition(sub))
	}
	if set.Len() != numSubs {
		//..
	}
	buf := new(bytes.Buffer)
	WriteVarUint(buf, threshold)
	WriteVarUint(buf, numSubs)
	for _, sub := range set {
		WriteVarUint(buf, sub.Weight())
		p, _ := sub.MarshalBinary()
		WriteVarOctet(buf, p)
		buf.WriteByte(0)
	}
	return buf.Bytes()
}

func (f *fulfillmentThreshold) Subfulfillments() Fulfillments { return f.subs }

func (f *fulfillmentThreshold) ThresholdSubs() (err error) {
	if f.subs != nil && f.threshold > 0 {
		return nil
	}
	if f.subs == nil && f.threshold == 0 {
		f.subs, f.threshold, err = ThresholdSubs(f.payload)
	} else {
		err = Errorf("cannot have %d subs, threshold=%d", len(f.subs), f.threshold)
	}
	return err
}

func ThresholdSubs(p []byte) (Fulfillments, int, error) {
	buf := bytes.NewBuffer(p)
	threshold, err := ReadVarUint(buf)
	if err != nil {
		return nil, 0, err
	}
	numSubs, err := ReadVarUint(buf)
	if err != nil {
		return nil, 0, err
	}
	subs := make(Fulfillments, numSubs)
	for i := 0; i < numSubs; i++ {
		weight, err := ReadVarUint(buf)
		if err != nil {
			return nil, 0, err
		}
		p, err := ReadVarOctet(buf)
		if err != nil {
			return nil, 0, err
		}
		subs[i], err = UnmarshalBinary(p, weight)
		if err != nil {
			return nil, 0, err
		}
		if _, err := buf.ReadByte(); err != nil {
			return nil, 0, err
		}
	}
	return subs, threshold, nil
}

// Sort subconditions then hash them..
func ThresholdHash(subs Fulfillments, threshold int) []byte {
	numSubs := len(subs)
	conds := make(Fulfillments, numSubs)
	for i, sub := range subs {
		sub.Init()
		conds[i] = GetCondition(sub)
	}
	sort.Sort(conds)
	hash := sha256.New()
	WriteUint32(hash, threshold)
	WriteVarUint(hash, numSubs)
	for _, c := range conds {
		WriteVarUint(hash, c.Weight())
		p, _ := c.MarshalBinary()
		hash.Write(p)
	}
	return hash.Sum(nil)[:]
}

func ThresholdSize(subs Fulfillments, threshold int) int {
	var i, j int
	numSubs := subs.Len()
	total := 4 + VarUintSize(numSubs) + numSubs
	j = Exp2(numSubs)
	extras := make([]int, j)
	thresholds := make([]int, j)
	for i, _ = range thresholds {
		thresholds[i] = threshold
	}
	for _, sub := range subs {
		p, _ := GetCondition(sub).MarshalBinary()
		conditionLen := len(p)
		total += conditionLen
		if weight := sub.Weight(); weight > 1 {
			total += VarUintSize(weight)
		}
		j >>= 1
		add := true
		p = make([]byte, sub.Size())
		extra := 2 + VarOctetLength(p) - conditionLen
		for i, _ = range extras {
			if add && thresholds[i] > 0 {
				extras[i] += extra
				thresholds[i] -= sub.Weight()
			}
			if (i+1)%j == 0 {
				add = !add
			}
		}
	}
	extra := 0
	for i, _ = range extras {
		if thresholds[i] <= 0 {
			if extras[i] > extra {
				extra = extras[i]
			}
		}
	}
	if extra == 0 {
		panic("Insufficient subconditions/weights to meet threshold")
	}
	total += extra
	return total
}

func (f *fulfillmentThreshold) Validate(p []byte) bool {
	if !f.fulfillment.Validate(nil) {
		return false
	}
	min, total := 0, 0
	subs, threshold := f.subs, f.threshold
	var subf Fulfillments
	for _, sub := range subs {
		if !sub.IsCondition() {
			subf = append(subf, sub)
			weight := sub.Weight()
			if weight < min || min == 0 {
				min = weight
			}
			total += min
		}
	}
	if total < threshold {
		return false
	}
	valid := 0
	buf := bytes.NewBuffer(p)
	for _, f := range subf {
		p, err := ReadVarOctet(buf)
		if err != nil {
			return false
		}
		if f.Validate(p) {
			valid += f.Weight()
		}
	}
	return valid >= threshold
}

// SHA256 Timeout
type fulfillmentTimeout struct {
	expire time.Time
	*fulfillment
}

func DefaultFulfillmentTimeout(expire time.Time) (*fulfillmentTimeout, error) {
	return NewFulfillmentTimeout(expire, 1)
}

func NewFulfillmentTimeout(expire time.Time, weight int) (*fulfillmentTimeout, error) {
	f := new(fulfillmentTimeout)
	f.expire = expire
	f.fulfillment = NewFulfillment(TIMEOUT_ID, f, []byte(Timestamp(expire)), weight)
	if err := f.Init(); err != nil {
		return nil, err
	}
	return f, nil
}

func (f *fulfillmentTimeout) Details() Data {
	details := f.fulfillment.Details()
	details.Set("expire_time", string(f.payload))
	return details
}

func (f *fulfillmentTimeout) Init() (err error) {
	f.expire, err = ParseTimestamp(string(f.payload))
	if err != nil {
		return err
	}
	f.bitmask = TIMEOUT_BITMASK
	f.hash = Sum256(f.payload)
	f.size = len(f.payload)
	return nil
}

func (f *fulfillmentTimeout) Validate(p []byte) bool {
	if !f.fulfillment.Validate(nil) {
		return false
	}
	t, err := ParseTimestamp(string(p))
	if err != nil {
		return false
	}
	return !t.After(f.expire)
}
