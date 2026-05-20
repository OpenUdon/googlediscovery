package googlediscovery

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Model is a parsed Google Discovery document. It preserves Discovery
// metadata directly instead of treating the service as OpenAPI.
type Model struct {
	DiscoveryVersion string
	Name             string
	Title            string
	Version          string
	Description      string
	ServerURL        string
	PathPrefix       string
	Schemas          map[string]map[string]any
	OAuth2Scopes     map[string]string
	Operations       []*Operation
}

// Operation is a flattened Discovery method with inherited resource/root
// metadata already applied.
type Operation struct {
	ID                string
	Name              string
	OperationID       string
	HTTPMethod        string
	Path              string
	Summary           string
	Description       string
	Tags              []string
	Parameters        []*Parameter
	RequestRef        string
	ResponseRef       string
	Scopes            []string
	MediaUpload       *MediaUpload
	MediaUploads      map[string]*MediaUpload
	RequestMediaType  string
	ResponseMediaType string
}

// Parameter describes a Discovery method parameter after inheritance and
// duplicate resolution.
type Parameter struct {
	Name         string
	OriginalName string
	Location     string
	Required     bool
	Description  string
	Schema       map[string]any
	Raw          map[string]any
}

// MediaUpload describes a Discovery media upload protocol.
type MediaUpload struct {
	Protocol  string
	Path      string
	Multipart bool
}

// Parse parses a Google Discovery document into native Discovery metadata.
func Parse(data []byte) (*Model, error) {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse discovery document: %w", err)
	}
	return ParseMap(raw)
}

// ParseMap parses an already-decoded Google Discovery document into native
// Discovery metadata.
func ParseMap(raw map[string]any) (*Model, error) {
	p := &discoveryParser{raw: raw}
	return p.parse()
}

// OperationByName returns an operation by its local operation identifier,
// sanitized operationId, or full Discovery method id.
func (m *Model) OperationByName(name string) (*Operation, bool) {
	if m == nil {
		return nil, false
	}
	name = strings.TrimSpace(name)
	for _, op := range m.Operations {
		if op != nil && (op.Name == name || op.OperationID == name || op.ID == name) {
			return op, true
		}
	}
	return nil, false
}

func (m *Model) Schema(name string) (map[string]any, bool) {
	if m == nil {
		return nil, false
	}
	schema, ok := m.Schemas[name]
	return schema, ok
}

type discoveryParser struct {
	raw   map[string]any
	model *Model
}

func (p *discoveryParser) parse() (*Model, error) {
	if p.raw == nil {
		return nil, fmt.Errorf("discovery document root must be an object")
	}
	serverURL, pathPrefix := discoveryServerAndPathPrefix(p.raw)
	model := &Model{
		DiscoveryVersion: stringValue(p.raw["discoveryVersion"]),
		Name:             stringValue(p.raw["name"]),
		Title:            firstNonEmptyString(stringValue(p.raw["title"]), stringValue(p.raw["name"])),
		Version:          stringValue(p.raw["version"]),
		Description:      stringValue(p.raw["description"]),
		ServerURL:        serverURL,
		PathPrefix:       pathPrefix,
		OAuth2Scopes:     discoveryOAuthScopeStrings(p.raw),
	}
	if model.Title == "" {
		model.Title = "Google Discovery API"
	}
	if model.ServerURL == "" {
		model.ServerURL = "https://www.googleapis.com"
	}
	p.model = model
	if err := p.parseSchemas(); err != nil {
		return nil, err
	}
	if err := p.parseOperations(); err != nil {
		return nil, err
	}
	return model, nil
}

func (p *discoveryParser) parseSchemas() error {
	schemas, ok, err := optionalMapField(p.raw, "schemas", "discovery document")
	if err != nil {
		return err
	}
	if !ok || len(schemas) == 0 {
		return nil
	}
	out := make(map[string]map[string]any, len(schemas))
	for _, name := range sortedKeys(schemas) {
		schema, ok, err := mapValueRequired(schemas[name], "schemas."+name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		converted, err := convertSchemaMap(schema, "schemas."+name)
		if err != nil {
			return err
		}
		out[name] = converted
	}
	p.model.Schemas = out
	return nil
}

func (p *discoveryParser) parseOperations() error {
	var rootParams []map[string]any
	if params, ok, err := optionalMapField(p.raw, "parameters", "discovery document"); err != nil {
		return err
	} else if ok {
		items, err := parameterListFromMap(params, "discovery document.parameters")
		if err != nil {
			return err
		}
		rootParams = items
	}
	if methods, ok, err := optionalMapField(p.raw, "methods", "discovery document"); err != nil {
		return err
	} else if ok {
		if err := p.addMethods(methods, rootParams, nil); err != nil {
			return err
		}
	}
	if resources, ok, err := optionalMapField(p.raw, "resources", "discovery document"); err != nil {
		return err
	} else if ok {
		if err := p.addResources(resources, rootParams, nil); err != nil {
			return err
		}
	}
	return nil
}

func (p *discoveryParser) addResources(resources map[string]any, inherited []map[string]any, tags []string) error {
	for _, name := range sortedKeys(resources) {
		resource, ok, err := mapValueRequired(resources[name], "resources."+name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		nextTags := append([]string(nil), tags...)
		if name != "" {
			nextTags = append(nextTags, name)
		}
		params := append([]map[string]any(nil), inherited...)
		if resParams, ok, err := optionalMapField(resource, "parameters", "resource "+name); err != nil {
			return err
		} else if ok {
			items, err := parameterListFromMap(resParams, "resource "+name+".parameters")
			if err != nil {
				return err
			}
			params = append(params, items...)
		}
		if methods, ok, err := optionalMapField(resource, "methods", "resource "+name); err != nil {
			return err
		} else if ok {
			if err := p.addMethods(methods, params, nextTags); err != nil {
				return err
			}
		}
		if subresources, ok, err := optionalMapField(resource, "resources", "resource "+name); err != nil {
			return err
		} else if ok {
			if err := p.addResources(subresources, params, nextTags); err != nil {
				return err
			}
		}
	}
	return nil
}

func (p *discoveryParser) addMethods(methods map[string]any, inherited []map[string]any, tags []string) error {
	for _, name := range sortedKeys(methods) {
		method, ok, err := mapValueRequired(methods[name], "methods."+name)
		if err != nil {
			return err
		}
		if !ok {
			continue
		}
		op, err := p.parseMethod(name, method, inherited, tags)
		if err != nil {
			return err
		}
		p.model.Operations = append(p.model.Operations, op)
	}
	return nil
}

func (p *discoveryParser) parseMethod(name string, method map[string]any, inherited []map[string]any, tags []string) (*Operation, error) {
	id := stringValue(method["id"])
	if id == "" {
		id = name
	}
	opID := sanitizeIdentifier(id)
	if opID == "" {
		opID = sanitizeIdentifier(name)
	}
	path := methodPath(p.model.PathPrefix, method)
	if path == "" {
		return nil, fmt.Errorf("discovery method %q missing path", id)
	}
	httpMethod := strings.ToUpper(stringValue(method["httpMethod"]))
	if httpMethod == "" {
		return nil, fmt.Errorf("discovery method %q missing httpMethod", id)
	}
	params := append([]map[string]any(nil), inherited...)
	if methodParams, ok, err := optionalMapField(method, "parameters", "method "+name); err != nil {
		return nil, err
	} else if ok {
		items, err := parameterListFromMap(methodParams, "method "+name+".parameters")
		if err != nil {
			return nil, err
		}
		params = append(params, items...)
	}
	convertedParams, err := discoveryParameters(params)
	if err != nil {
		return nil, err
	}
	uploads := discoveryMediaUploads(method)
	upload := preferredMediaUpload(uploads)
	requestRef := discoveryRequestRef(method)
	op := &Operation{
		ID:                id,
		Name:              opID,
		OperationID:       opID,
		HTTPMethod:        httpMethod,
		Path:              path,
		Summary:           summarize(stringValue(method["description"]), name),
		Description:       stringValue(method["description"]),
		Tags:              append([]string(nil), tags...),
		Parameters:        convertedParams,
		RequestRef:        requestRef,
		ResponseRef:       discoveryResponseRef(method),
		Scopes:            stringSliceValue(method["scopes"]),
		MediaUpload:       upload,
		MediaUploads:      uploads,
		RequestMediaType:  discoveryRequestMediaType(requestRef, upload),
		ResponseMediaType: "application/json",
	}
	if op.ResponseRef == "" {
		op.ResponseMediaType = ""
	}
	return op, nil
}

func discoveryParameters(params []map[string]any) ([]*Parameter, error) {
	if len(params) == 0 {
		return nil, nil
	}
	type key struct {
		name string
		in   string
	}
	indexes := map[key]int{}
	out := make([]*Parameter, 0, len(params))
	for _, raw := range params {
		name := sanitizeParameterName(stringValue(raw["name"]))
		location := strings.ToLower(stringValue(firstNonEmpty(raw["location"], raw["in"])))
		if name == "" || location == "" {
			continue
		}
		schema, err := convertDiscoveryParamSchema(raw)
		if err != nil {
			return nil, err
		}
		param := &Parameter{
			Name:         name,
			OriginalName: stringValue(raw["name"]),
			Location:     location,
			Description:  stringValue(raw["description"]),
			Schema:       schema,
			Raw:          cloneMap(raw),
		}
		if req, ok := boolValue(raw["required"]); ok {
			param.Required = req
		}
		k := key{name: name, in: location}
		if idx, ok := indexes[k]; ok {
			out[idx] = param
			continue
		}
		indexes[k] = len(out)
		out = append(out, param)
	}
	return out, nil
}

func discoveryRequestRef(method map[string]any) string {
	request := mapValueOrNil(method["request"])
	return stringValue(request["$ref"])
}

func discoveryResponseRef(method map[string]any) string {
	response := mapValueOrNil(method["response"])
	return stringValue(response["$ref"])
}

func discoveryMediaUploads(method map[string]any) map[string]*MediaUpload {
	mediaUpload, ok := mapValue(method["mediaUpload"])
	if !ok {
		return nil
	}
	protocols, ok := mapValue(mediaUpload["protocols"])
	if !ok {
		return nil
	}
	out := map[string]*MediaUpload{}
	for _, protocol := range []string{"simple", "resumable"} {
		item, ok := mapValue(protocols[protocol])
		if !ok {
			continue
		}
		multipart, _ := boolValue(item["multipart"])
		out[protocol] = &MediaUpload{
			Protocol:  protocol,
			Path:      stringValue(item["path"]),
			Multipart: multipart,
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func preferredMediaUpload(uploads map[string]*MediaUpload) *MediaUpload {
	if len(uploads) == 0 {
		return nil
	}
	if upload := uploads["simple"]; upload != nil {
		return upload
	}
	if upload := uploads["resumable"]; upload != nil {
		return upload
	}
	return nil
}

func discoveryRequestMediaType(requestRef string, upload *MediaUpload) string {
	if upload != nil {
		if upload.Multipart {
			return "multipart/related"
		}
		return "application/octet-stream"
	}
	if requestRef != "" {
		return "application/json"
	}
	return ""
}

func discoveryOAuthScopeStrings(raw map[string]any) map[string]string {
	scopes := discoveryOAuthScopes(raw)
	if len(scopes) == 0 {
		return nil
	}
	out := make(map[string]string, len(scopes))
	for _, name := range sortedKeys(scopes) {
		out[name] = stringValue(scopes[name])
	}
	return out
}

func firstNonEmptyString(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func mapValueOrNil(v any) map[string]any {
	m, _ := mapValue(v)
	return m
}
