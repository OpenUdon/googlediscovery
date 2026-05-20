package googlediscovery

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var numericSchemaConstraintKeys = map[string]bool{
	"minimum":   true,
	"maximum":   true,
	"minLength": true,
	"maxLength": true,
	"minItems":  true,
	"maxItems":  true,
}

func discoveryServerAndPathPrefix(raw map[string]any) (serverURL, pathPrefix string) {
	rootURL := trimTrailingSlash(stringValue(raw["rootUrl"]))
	servicePath := trimSlashes(stringValue(raw["servicePath"]))
	baseURL := trimTrailingSlash(stringValue(raw["baseUrl"]))

	if rootURL != "" {
		if servicePath != "" {
			pathPrefix = "/" + servicePath
		}
		return rootURL, pathPrefix
	}
	if baseURL != "" {
		return baseURL, ""
	}
	return "https://www.googleapis.com", ""
}

func discoveryOAuthScopes(raw map[string]any) (map[string]any, error) {
	auth, ok, err := optionalMapField(raw, "auth", "discovery document")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	oauth2, ok, err := optionalMapField(auth, "oauth2", "discovery document.auth")
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, nil
	}
	scopes, ok, err := optionalMapField(oauth2, "scopes", "discovery document.auth.oauth2")
	if err != nil {
		return nil, err
	}
	if !ok || len(scopes) == 0 {
		return nil, nil
	}
	out := make(map[string]any, len(scopes))
	for _, name := range sortedKeys(scopes) {
		description := ""
		scope, ok, err := mapValueRequired(scopes[name], "discovery document.auth.oauth2.scopes."+name)
		if err != nil {
			return nil, err
		}
		if ok {
			description = stringValue(scope["description"])
		}
		out[name] = description
	}
	return out, nil
}

func methodPath(pathPrefix string, method map[string]any) (string, error) {
	uploads, err := discoveryMediaUploads(method)
	if err != nil {
		return "", err
	}
	if upload := preferredMediaUpload(uploads); upload != nil && upload.Path != "" {
		return upload.Path, nil
	}
	p := strings.TrimSpace(stringValue(method["path"]))
	if p == "" {
		return "", nil
	}
	if strings.HasPrefix(p, "http://") || strings.HasPrefix(p, "https://") {
		return p, nil
	}
	p = "/" + strings.TrimPrefix(p, "/")
	if pathPrefix == "" {
		return p, nil
	}
	return "/" + strings.Trim(pathPrefix, "/") + p, nil
}

func convertSchemaMap(schema map[string]any, path string) (map[string]any, error) {
	return convertSchemaMapDepth(schema, path, 0)
}

func convertSchemaMapDepth(schema map[string]any, path string, depth int) (map[string]any, error) {
	if schema == nil {
		return nil, nil
	}
	if depth > maxDiscoveryNestingDepth {
		return nil, fmt.Errorf("%s exceeds schema nesting limit of %d", path, maxDiscoveryNestingDepth)
	}
	out := map[string]any{}
	if ref := stringValue(schema["$ref"]); ref != "" {
		out["$ref"] = "#/components/schemas/" + ref
	}
	for _, key := range []string{
		"type", "format", "description", "title", "default", "example",
		"pattern", "nullable", "deprecated", "readOnly", "writeOnly", "enumDescriptions",
		"minimum", "maximum", "minLength", "maxLength", "minItems",
		"maxItems", "uniqueItems",
	} {
		if v, ok := schema[key]; ok {
			if numericSchemaConstraintKeys[key] {
				normalized, ok := normalizeNumericJSON(v)
				if !ok {
					return nil, fmt.Errorf("%s.%s must be numeric", path, key)
				}
				out[key] = normalized
				continue
			}
			out[key] = v
		}
	}
	if v, ok := schema["enum"]; ok {
		out["enum"] = v
	}
	if v, ok := schema["required"]; ok {
		out["required"] = v
	}
	if v, ok := schema["properties"]; ok {
		props, ok, err := mapValueRequired(v, path+".properties")
		if err != nil {
			return nil, err
		}
		if ok {
			outProps := make(map[string]any, len(props))
			for _, name := range sortedKeys(props) {
				prop, ok, err := mapValueRequired(props[name], path+".properties."+name)
				if err != nil {
					return nil, err
				}
				if ok {
					converted, err := convertSchemaMapDepth(prop, path+".properties."+name, depth+1)
					if err != nil {
						return nil, err
					}
					outProps[name] = converted
				}
			}
			if len(outProps) > 0 {
				out["properties"] = outProps
			}
		}
	}
	if v, ok := schema["items"]; ok {
		items, ok, err := mapValueRequired(v, path+".items")
		if err != nil {
			return nil, err
		}
		if ok {
			converted, err := convertSchemaMapDepth(items, path+".items", depth+1)
			if err != nil {
				return nil, err
			}
			out["items"] = converted
		}
	}
	if v, ok := schema["allOf"]; ok {
		outArr, err := convertSchemaList(v, path+".allOf", depth+1)
		if err != nil {
			return nil, err
		}
		if len(outArr) > 0 {
			out["allOf"] = outArr
		}
	}
	if v, ok := schema["oneOf"]; ok {
		outArr, err := convertSchemaList(v, path+".oneOf", depth+1)
		if err != nil {
			return nil, err
		}
		if len(outArr) > 0 {
			out["oneOf"] = outArr
		}
	}
	if v, ok := schema["anyOf"]; ok {
		outArr, err := convertSchemaList(v, path+".anyOf", depth+1)
		if err != nil {
			return nil, err
		}
		if len(outArr) > 0 {
			out["anyOf"] = outArr
		}
	}
	if v, ok := schema["additionalProperties"]; ok {
		switch t := v.(type) {
		case bool:
			out["additionalProperties"] = t
		case map[string]any:
			converted, err := convertSchemaMapDepth(t, path+".additionalProperties", depth+1)
			if err != nil {
				return nil, err
			}
			out["additionalProperties"] = converted
		default:
			return nil, fmt.Errorf("%s.additionalProperties must be a boolean or object", path)
		}
	}
	return out, nil
}

func convertSchemaList(value any, path string, depth int) ([]any, error) {
	arr, ok := sliceValue(value)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", path)
	}
	out := make([]any, 0, len(arr))
	for i, item := range arr {
		m, ok, err := mapValueRequired(item, fmt.Sprintf("%s[%d]", path, i))
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		converted, err := convertSchemaMapDepth(m, fmt.Sprintf("%s[%d]", path, i), depth)
		if err != nil {
			return nil, err
		}
		out = append(out, converted)
	}
	return out, nil
}

func sanitizeParameterName(name string) string {
	if len(name) == 0 {
		return name
	}
	switch name[0:1] {
	case "{", "[", "<", "(", "$", "#", "@", "%", "!", "~", "`", "&", "^", "*", "+", "=", "|", ";", ":", ",", ".":
		return "x_" + name[1:]
	default:
		return name
	}
}

func convertDiscoveryParamSchema(param map[string]any) (map[string]any, error) {
	schema := map[string]any{}
	if t := stringValue(param["type"]); t != "" {
		if repeated, _ := boolValue(param["repeated"]); repeated {
			schema["type"] = "array"
			schema["items"] = map[string]any{"type": t}
		} else {
			schema["type"] = t
		}
	}
	for _, key := range []string{"format", "description", "default", "pattern", "enumDescriptions"} {
		if v, ok := param[key]; ok {
			schema[key] = v
		}
	}
	if v, ok := param["enum"]; ok {
		schema["enum"] = v
	}
	if v, ok := param["items"]; ok {
		itemMap, ok, err := mapValueRequired(v, "parameter.items")
		if err != nil {
			return nil, err
		}
		if ok {
			converted, err := convertSchemaMap(itemMap, "parameter.items")
			if err != nil {
				return nil, err
			}
			schema["items"] = converted
		}
	}
	for _, key := range []string{"minimum", "maximum", "minLength", "maxLength"} {
		if v, ok := param[key]; ok {
			if normalized, ok := normalizeNumericJSON(v); ok {
				schema[key] = normalized
				continue
			}
			schema[key] = v
		}
	}
	if len(schema) == 0 {
		return nil, nil
	}
	return schema, nil
}

func normalizeNumericJSON(v any) (any, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case float32:
		return float64(t), true
	case int:
		return float64(t), true
	case int8:
		return float64(t), true
	case int16:
		return float64(t), true
	case int32:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint:
		return float64(t), true
	case uint8:
		return float64(t), true
	case uint16:
		return float64(t), true
	case uint32:
		return float64(t), true
	case uint64:
		return float64(t), true
	case json.Number:
		if s := strings.TrimSpace(t.String()); s != "" {
			if n, err := strconv.ParseFloat(s, 64); err == nil {
				return n, true
			}
		}
	case string:
		if s := strings.TrimSpace(t); s != "" {
			if n, err := strconv.ParseFloat(s, 64); err == nil {
				return n, true
			}
		}
	}
	return nil, false
}

func parameterListFromMap(params map[string]any, path string) ([]map[string]any, error) {
	if len(params) == 0 {
		return nil, nil
	}
	names := sortedKeys(params)
	out := make([]map[string]any, 0, len(names))
	for _, name := range names {
		param, ok, err := mapValueRequired(params[name], path+"."+name)
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		param = cloneMap(param)
		param["name"] = name
		out = append(out, param)
	}
	return out, nil
}

func cloneMap(in map[string]any) map[string]any {
	if in == nil {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func stringValue(v any) string {
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	default:
		return ""
	}
}

func firstNonEmpty(values ...any) any {
	for _, v := range values {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func boolValue(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

func mapValue(v any) (map[string]any, bool) {
	switch t := v.(type) {
	case map[string]any:
		return t, true
	default:
		return nil, false
	}
}

func optionalMapField(parent map[string]any, key, context string) (map[string]any, bool, error) {
	if parent == nil {
		return nil, false, nil
	}
	value, exists := parent[key]
	if !exists || value == nil {
		return nil, false, nil
	}
	m, ok := mapValue(value)
	if !ok {
		return nil, false, fmt.Errorf("%s field %q must be an object", context, key)
	}
	return m, true, nil
}

func mapValueRequired(value any, context string) (map[string]any, bool, error) {
	if value == nil {
		return nil, false, nil
	}
	m, ok := mapValue(value)
	if !ok {
		return nil, false, fmt.Errorf("%s must be an object", context)
	}
	return m, true, nil
}

func sliceValue(v any) ([]any, bool) {
	switch t := v.(type) {
	case []any:
		return t, true
	default:
		return nil, false
	}
}

func stringSliceValue(v any) []string {
	if items, ok := v.([]string); ok {
		return append([]string(nil), items...)
	}
	items, ok := sliceValue(v)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if s := stringValue(item); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func trimTrailingSlash(s string) string {
	return strings.TrimRight(strings.TrimSpace(s), "/")
}

func trimSlashes(s string) string {
	return strings.Trim(strings.TrimSpace(s), "/")
}

func summarize(description, fallback string) string {
	if description == "" {
		return fallback
	}
	s := strings.TrimSpace(description)
	for _, sep := range []string{"\n", ". "} {
		if idx := strings.Index(s, sep); idx > 0 {
			return strings.TrimSpace(s[:idx+1])
		}
	}
	return s
}

var nonID = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func sanitizeIdentifier(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	s = nonID.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")
	if s == "" {
		return ""
	}
	if s[0] >= '0' && s[0] <= '9' {
		s = "op_" + s
	}
	return strings.ToLower(s)
}
