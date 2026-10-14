package api

import (
	"context"
	"encoding/json"
	"net/http"
)

func Call[R any](c *Client, ctx context.Context, rcpOpts RPCOpts, result *R) (*R, error) {
	// Mutating RPCs share the CRUD write lock through their reconfigure window.
	// GET requests can collect independent appliance state concurrently.
	if rcpOpts.Method != http.MethodGet {
		if err := GlobalMutexKV.Lock(clientMutexKey, ctx); err != nil {
			return nil, err
		}
		defer GlobalMutexKV.Unlock(clientMutexKey, ctx)
	}

	// Get generic data
	var reqData json.RawMessage

	var body interface{}
	if len(rcpOpts.BodyParameters) > 0 {
		body = rcpOpts.BodyParameters
	}

	err := c.doRequest(ctx, rcpOpts.Method, rcpOpts.EndpointURL(), body, &reqData)

	// Handle request errors
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal(reqData, result); err != nil {
		return nil, err
	}

	return result, nil
}
