package block

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/gocty"

	"github.com/tfsec/tfsec/internal/app/tfsec/debug"
)

type Attribute struct {
	hclAttribute *hclsyntax.Attribute
	ctx          *hcl.EvalContext
}

func NewAttribute(attr *hclsyntax.Attribute, ctx *hcl.EvalContext) *Attribute {
	return &Attribute{
		hclAttribute: attr,
		ctx:          ctx,
	}
}

func (attr *Attribute) IsLiteral() bool {
	return len(attr.hclAttribute.Expr.Variables()) == 0
}

func (attr *Attribute) Type() cty.Type {
	return attr.Value().Type()
}

func (attr *Attribute) Value() (ctyVal cty.Value) {
	if attr == nil {
		return cty.NilVal
	}
	defer func() {
		if err := recover(); err != nil {
			ctyVal = cty.NilVal
		}
	}()
	ctyVal, _ = attr.hclAttribute.Expr.Value(attr.ctx)
	if !ctyVal.IsKnown() {
		return cty.NilVal
	}
	return ctyVal
}

func (attr *Attribute) Range() Range {
	return Range{
		Filename:  attr.hclAttribute.SrcRange.Filename,
		StartLine: attr.hclAttribute.SrcRange.Start.Line,
		EndLine:   attr.hclAttribute.SrcRange.End.Line,
	}
}

func (attr *Attribute) Name() string {
	return attr.hclAttribute.Name
}

func (attr *Attribute) Contains(checkValue interface{}, equalityOptions ...EqualityOption) bool {
	ignoreCase := false
	for _, option := range equalityOptions {
		if option == IgnoreCase {
			ignoreCase = true
		}
	}
	val := attr.Value()
	if val.IsNull() {
		return false
	}

	if val.Type().IsObjectType() || val.Type().IsMapType() {

		switch t := checkValue.(type) {
		case map[interface{}]interface{}:

			for k, v := range t {

				valueMap := val.AsValueMap()
				for key, value := range valueMap {
					rawValue := getRawValue(value)
					if key == k && rawValue == v {
						return true
					}
				}
			}
			return false
		default:
			valueMap := val.AsValueMap()
			for key := range valueMap {
				if key == checkValue {
					return true
				}
			}
			return false
		}
	}

	stringToLookFor := fmt.Sprintf("%v", checkValue)
	if val.Type().IsListType() || val.Type().IsTupleType() {
		valueSlice := val.AsValueSlice()
		for _, value := range valueSlice {
			stringToTest := value
			if value.Type().IsObjectType() || value.Type().IsMapType() {
				valueMap := value.AsValueMap()
				stringToTest = valueMap["key"]
			}
			if value.Type().HasDynamicTypes() {
				// References without a value can't logically "contain" a some string to check against.
				return false
			}
			if ignoreCase && containsIgnoreCase(stringToTest.AsString(), stringToLookFor) {
				return true
			}
			if strings.Contains(stringToTest.AsString(), stringToLookFor) {
				return true
			}
		}
		return false
	}

	if ignoreCase && containsIgnoreCase(val.AsString(), stringToLookFor) {
		return true
	}

	return strings.Contains(val.AsString(), stringToLookFor)
}

func containsIgnoreCase(left, substring string) bool {
	return strings.Contains(strings.ToLower(left), strings.ToLower(substring))
}

func (attr *Attribute) StartsWith(prefix interface{}) bool {
	if attr.Value().Type() == cty.String {
		return strings.HasPrefix(attr.Value().AsString(), fmt.Sprintf("%v", prefix))
	}
	return false
}

func (attr *Attribute) EndsWith(suffix interface{}) bool {
	if attr.Value().Type() == cty.String {
		return strings.HasSuffix(attr.Value().AsString(), fmt.Sprintf("%v", suffix))
	}
	return false
}

type EqualityOption int

const (
	IgnoreCase EqualityOption = iota
)

func (attr *Attribute) Equals(checkValue interface{}, equalityOptions ...EqualityOption) bool {
	if attr.Value().Type() == cty.String {
		for _, option := range equalityOptions {
			if option == IgnoreCase {
				return strings.EqualFold(strings.ToLower(attr.Value().AsString()), strings.ToLower(fmt.Sprintf("%v", checkValue)))
			}
		}
		return strings.EqualFold(attr.Value().AsString(), fmt.Sprintf("%v", checkValue))
	}
	if attr.Value().Type() == cty.Bool {
		return attr.Value().True() == checkValue
	}
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}
		return attr.Value().RawEquals(checkNumber)
	}
	return false
}

func (attr *Attribute) RegexMatches(pattern interface{}) bool {
	patternVal := fmt.Sprintf("%v", pattern)
	re, err := regexp.Compile(patternVal)
	if err != nil {
		debug.Log("an error occurred while compiling the regex: %s", err)
		return false
	}
	if attr.Value().Type() == cty.String {
		match := re.MatchString(attr.Value().AsString())
		return match
	}
	return false
}

func (attr *Attribute) IsAny(options ...interface{}) bool {
	if attr.Value().Type() == cty.String {
		value := attr.Value().AsString()
		for _, option := range options {
			if option == value {
				return true
			}
		}
	}
	if attr.Value().Type() == cty.Number {
		for _, option := range options {
			checkValue, err := gocty.ToCtyValue(option, cty.Number)
			if err != nil {
				debug.Log("Error converting number for equality check. %s", err)
				return false
			}
			if attr.Value().RawEquals(checkValue) {
				return true
			}
		}
	}
	return false
}

func (attr *Attribute) IsNone(options ...interface{}) bool {
	if attr.Value().Type() == cty.String {
		for _, option := range options {
			if option == attr.Value().AsString() {
				return false
			}
		}
	}
	if attr.Value().Type() == cty.Number {
		for _, option := range options {
			checkValue, err := gocty.ToCtyValue(option, cty.Number)
			if err != nil {
				debug.Log("Error converting number for equality check. %s", err)
				return false
			}
			if attr.Value().RawEquals(checkValue) {
				return false
			}

		}
	}

	return true
}

func (attr *Attribute) IsTrue() bool {
	switch attr.Value().Type() {
	case cty.Bool:
		return attr.Value().True()
	case cty.String:
		val := attr.Value().AsString()
		val = strings.Trim(val, "\"")
		return strings.ToLower(val) == "true"
	}
	return false
}

func (attr *Attribute) IsFalse() bool {
	switch attr.Value().Type() {
	case cty.Bool:
		return attr.Value().False()
	case cty.String:
		val := attr.Value().AsString()
		val = strings.Trim(val, "\"")
		return strings.ToLower(val) == "false"
	}
	return false
}

func (attr *Attribute) IsEmpty() bool {
	if attr.Value().Type() == cty.String {
		return len(attr.Value().AsString()) == 0
	}
	if attr.Type().IsListType() || attr.Type().IsTupleType() {
		return len(attr.Value().AsValueSlice()) == 0
	}
	if attr.Type().IsMapType() || attr.Type().IsObjectType() {
		return len(attr.Value().AsValueMap()) == 0
	}
	if attr.Value().Type() == cty.Number {
		// a number can't ever be empty
		return false
	}
	if attr.Value().IsNull() {
		switch t := attr.hclAttribute.Expr.(type) {
		case *hclsyntax.FunctionCallExpr:
			return false
		case *hclsyntax.ScopeTraversalExpr:
			return false
		case *hclsyntax.ConditionalExpr:
			return false
		case *hclsyntax.TemplateExpr:
			// walk the parts of the expression to ensure that it has a literal value
			for _, p := range t.Parts {
				part := p.(*hclsyntax.LiteralValueExpr)
				if part != nil && !part.Val.IsNull() {
					return false
				}
			}
		}
	}
	return true
}

func (attr *Attribute) MapValue(mapKey string) cty.Value {
	if attr.Type().IsObjectType() || attr.Type().IsMapType() {
		attrMap := attr.Value().AsValueMap()
		for key, value := range attrMap {
			if key == mapKey {
				return value
			}
		}
	}
	return cty.StringVal("")
}

func (attr *Attribute) LessThan(checkValue interface{}) bool {
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().LessThan(checkNumber).True()
	}
	return false
}

func (attr *Attribute) LessThanOrEqualTo(checkValue interface{}) bool {
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().LessThanOrEqualTo(checkNumber).True()
	}
	return false
}

func (attr *Attribute) GreaterThan(checkValue interface{}) bool {
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().GreaterThan(checkNumber).True()
	}
	return false
}

func (attr *Attribute) GreaterThanOrEqualTo(checkValue interface{}) bool {
	if attr.Value().Type() == cty.Number {
		checkNumber, err := gocty.ToCtyValue(checkValue, cty.Number)
		if err != nil {
			debug.Log("Error converting number for equality check. %s", err)
			return false
		}

		return attr.Value().GreaterThanOrEqualTo(checkNumber).True()
	}
	return false
}

func (attr *Attribute) IsDataBlockReference() bool {
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		split := t.Traversal.SimpleSplit()
		return split.Abs.RootName() == "data"
	}
	return false
}

func (attr *Attribute) Reference() (*Reference, error) {
	var refParts []string
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		for _, p := range t.Traversal {
			switch part := p.(type) {
			case hcl.TraverseRoot:
				refParts = append(refParts, part.Name)
			case hcl.TraverseAttr:
				refParts = append(refParts, part.Name)
			}
		}
	default:
		return nil, fmt.Errorf("not a reference: no scope traversal")
	}
	if len(refParts) == 0 {
		return nil, fmt.Errorf("reference has zero parts")
	}
	return newReference(refParts), nil

}

func (attr *Attribute) IsResourceBlockReference(resourceType string) bool {
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		split := t.Traversal.SimpleSplit()
		return split.Abs.RootName() == resourceType
	}
	return false
}

func (attr *Attribute) GetReferencedResourceBlockType() (string, error) {
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		split := t.Traversal.SimpleSplit()
		return split.Abs.RootName(), nil
	}
	return "", fmt.Errorf("not referenced block found on the attribute")
}

func (attr *Attribute) GetReferencedResourceBlocksName() (string, error) {
	switch t := attr.hclAttribute.Expr.(type) {
	case *hclsyntax.ScopeTraversalExpr:
		parts := t.Traversal.SimpleSplit()
		for _, p := range parts.Rel {
			switch part := p.(type) {
			case hcl.TraverseAttr:
				// the first name on the Rel is the label for the attribute, so return that
				return part.Name, nil
			}
		}
	}
	return "", fmt.Errorf("no referenced block found on the atteibute")
}

func (attr *Attribute) ReferencesBlock(b *Block) bool {
	ref, err := attr.Reference()
	if err != nil {
		return false
	}
	return ref.RefersTo(b)
}

func getRawValue(value cty.Value) interface{} {
	typeName := value.Type().FriendlyName()

	switch typeName {
	case "string":
		return value.AsString()
	case "number":
		return value.AsBigFloat()
	case "bool":
		return value.True()
	}

	return value
}
