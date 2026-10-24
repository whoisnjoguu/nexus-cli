package hitl

import (
	"context"
	"reflect"
	"sync"
)

// Any combines approvers: each request is offered to all of them concurrently and the first
// decision wins. The others are cancelled and Any waits for them to return before returning, so a
// TTY prompt is torn down before the caller proceeds. Nil approvers — including typed nils such as
// a nil *TTYApprover stored in the interface — are ignored. With no approvers the result is
// DenyAll; with one it is that approver. Requests get an ID and creation time if missing, so every
// approver sees the same request.
func Any(approvers ...Approver) Approver {
	var list []Approver
	for _, a := range approvers {
		if !isNil(a) {
			list = append(list, a)
		}
	}
	switch len(list) {
	case 0:
		return DenyAll
	case 1:
		return list[0]
	}
	return ApproverFunc(func(ctx context.Context, req Request) Decision {
		req = fillRequest(req)
		cctx, cancel := context.WithCancel(ctx)
		defer cancel()

		results := make(chan Decision, len(list))
		var wg sync.WaitGroup
		for _, a := range list {
			wg.Add(1)
			go func(a Approver) {
				defer wg.Done()
				d := Deny
				defer func() {
					if recover() != nil {
						d = Deny
					}
					results <- d
				}()
				d = a.Approve(cctx, req)
			}(a)
		}

		d := <-results
		cancel()
		wg.Wait()
		return d
	})
}

func isNil(a Approver) bool {
	if a == nil {
		return true
	}
	v := reflect.ValueOf(a)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan, reflect.Interface:
		return v.IsNil()
	}
	return false
}
