from asn1crypto.core import Sequence, SequenceOf, Enumerated, Choice, OctetString, UTF8String, Integer, Null, Any, ObjectIdentifier, Boolean, SetOf, Asn1Value

def options(**kwargs):
    if 'tag' in kwargs and 'tag_type' not in kwargs:
        kwargs['tag_type'] = 'implicit'
        kwargs['class_'] = 2
    return kwargs

class LDAPString(OctetString):
    pass

class LDAPDN(LDAPString):
    pass

class LDAPOID(OctetString):
    pass

class SaslCredentials(Sequence):
    _fields = [
        ('mechanism', OctetString),
        ('credentials', OctetString, {'optional':True}),
    ]

class AuthenticationChoice(Choice):
    _alternatives = [
        ('simple', OctetString,   options(tag=0)),
        ('sasl', SaslCredentials, options(tag=3)),
    ]

class URI(LDAPString):
    pass

class Referral(SequenceOf):
    _child_spec = URI

class ResultCode(Enumerated):
    _map = {
        0:  'success',
        1:  'operationError',
        2:  'protocolError',
        3:  'timeLimitExceeded',
        4:  'sizeLimitExceeded',
        5:  'compareFalse',
        6:  'compareTrue',
        7:  'authMethodNotSupported',
        8:  'strongerAuthRequired',
        10: 'referral',
        11: 'adminLimitExceeded',
        12: 'unavailableCriticalExtension',
        13: 'confidentialityRequired',
        14: 'saslBindInProgress',
        16: 'noSuchAttribute',
        17: 'undefinedAttributeType',
        18: 'inappropriateMatching',
        19: 'constraintViolation',
        20: 'attributeOrValueExists',
        21: 'invalidAttributeSyntax',
        32: 'noSuchObject',
        33: 'aliasProblem',
        34: 'invalidDNSyntax',
        36: 'aliasDereferencingProblem',
        48: 'inappropriateAuthentication',
        49: 'invalidCredentials',
        50: 'insufficientAccessRights',
        51: 'busy',
        52: 'unavailable',
        53: 'unwillingToPerform',
        54: 'loopDetect',
        64: 'namingViolation',
        65: 'objectClassViolation',
        66: 'notAllowedOnNonLeaf',
        67: 'notAllowedOnRDN',
        68: 'entryAlreadyExists',
        69: 'objectClassModsProhibited',
        71: 'affectsMultipleDSAs',
        80: 'other',
    }

class LDAPResult(Sequence):
    _fields = [
        ('resultCode', ResultCode),
        ('matchedDN',  LDAPDN),
        ('diagnosticMessage', LDAPString),
        ('referral', Referral, options(tag=3, optional=True)),
    ]

class Control(Sequence):
    _fields = [
        ('controlType', LDAPOID),
        ('criticality', Boolean,      options(default=False)),
        ('controlValue', OctetString, options(optional=True)),
    ]

class Controls(SequenceOf):
    _child_spec = Control

class MessageID(Integer):
    pass

class SearchScope(Enumerated):
    _map = {
        0: 'baseObject',
        1: 'singleLevel',
        2: 'wholeSubtree',
    }

class SearchDerefAliases(Enumerated):
    _map = {
        0: 'neverDerefAliases',
        1: 'derefInSearching',
        2: 'derefFindingBaseObj',
        3: 'derefAlways',
    }

class AttributeSelection(SequenceOf):
    _child_spec = LDAPString        # '*' & '1.1' are special

class AssertionValue(OctetString):
    pass

class MatchingRuleId(LDAPString):
    pass

class AttributeDescription(LDAPString):
    pass

class AttributeValue(OctetString):
    pass

class AttributeValueAssertion(Sequence):
    _fields = [
        ('attributeDesc', AttributeDescription),
        ('assertionValue', AssertionValue),
    ]

class Substring(Choice):
    _alternatives = [
        ('initial', AssertionValue, options(tag=0)),
        ('any',     AssertionValue, options(tag=1)),
        ('final',   AssertionValue, options(tag=2)),
    ]

class MatchingRuleAssertion(Sequence):
    _fields = [
        ('matchingRule', MatchingRuleId, options(optional=True)),
        ('type', AttributeDescription,   options(optional=True)),
        ('matchValue', AssertionValue),
        ('dnAttributes', Boolean,        options(default=False)),
    ]

class SequenceOfSubstring(SequenceOf):
    _child_spec = Substring

class SubstringFilter(Sequence):
    _fields = [
        ('type', AttributeDescription),
        ('substrings', SequenceOfSubstring),
    ]

class SetOfFilter(SetOf):
    pass
class Filter(Choice):
    _alternatives = [
        ('and', SetOfFilter,                        options(tag=0)),
        ('or',  SetOfFilter,                        options(tag=1)),
        ('not', SetOfFilter,                        options(tag=2)),
        ('equalityMatch', AttributeValueAssertion,  options(tag=3)),
        ('substrings', SubstringFilter,             options(tag=4)),
        ('greaterOrEqual', AttributeValueAssertion, options(tag=5)),
        ('lessOrEqual', AttributeValueAssertion,    options(tag=6)),
        ('present', AttributeDescription,           options(tag=7)),
        ('approxMatch', AttributeValueAssertion,    options(tag=8)),
        ('extensibleMatch', MatchingRuleAssertion,  options(tag=9)),
    ]
SetOfFilter._child_spec = Filter

class SetOfAttributeValue(SetOf):
    _child_spec = AttributeValue

class PartialAttribute(Sequence):
    _fields = [
        ('type', AttributeDescription),
        ('vals', SetOfAttributeValue),
    ]

class PartialAttributeList(SequenceOf):
    _child_spec = PartialAttribute

 
class BindRequest(Sequence):
    class_, tag = 1, 0
    _fields = [
        ('version', Integer),
        ('name', LDAPDN),
        ('authentication', AuthenticationChoice ),
    ]

class BindResponse(Sequence):
    class_, tag = 1, 1
    _fields = LDAPResult._fields + [
        ('serverSaslCreds', OctetString, options(tag=7, optional=True)),
    ]

class SearchRequest(Sequence):
    class_, tag = 1,3
    _fields = [
        ('baseObject', LDAPDN),
        ('scope', SearchScope),
        ('derefAliases', SearchDerefAliases),
        ('sizeLimit', Integer),
        ('timeLimit', Integer),
        ('typesOnly', Boolean),
        ('filter', Filter),
        ('attributes', AttributeSelection), 
    ]

class SearchResultEntry(Sequence):
    class_, tag = 1, 4
    _fields = [
        ('objectName', LDAPDN),
        ('attributes', PartialAttributeList)
    ]

class SearchResultDone(LDAPResult):
    class_, tag = 1, 5

class ExtendedRequest(Sequence):
    class_, tag = 1, 23
    _fields = [
        ('requestName', LDAPOID,      options(tag=0)),
        ('requestValue', OctetString, options(tag=1, optional=True)),
    ]

class ExtendedResponse(Sequence):
    class_, tag = 1, 24
    _fields = LDAPResult._fields + [
        ('responseName', LDAPOID,      options(tag=10, optional=True)),
        ('responseValue', OctetString, options(tag=11, optional=True)),
    ]

class ProtocolOp(Choice):
    _alternatives = [
        ('bindRequest',         BindRequest),
        ('bindResponse',        BindResponse),
        ('unbindRequest',       Null),
        ('searchRequest',       SearchRequest),
        ('searchResEntry',      SearchResultEntry),
        ('searchResDone',       SearchResultDone),
        ('searchResRef',        Null),
        ('modifyRequest',       Null), #ModifyRequest,
        ('modifyResponse',      Null), #ModifyResponse,
        ('addRequest',          Null), #AddRequest,
        ('addResponse',         Null), #AddResponse,
        ('delRequest',          Null), #DelRequest,
        ('delResponse',         Null), #DelResponse,
        ('modDNRequest',        Null), #ModifyDNRequest,
        ('modDNResponse',       Null), #ModifyDNResponse,
        ('compareRequest',      Null), #CompareRequest,
        ('compareResponse',     Null), #CompareResponse,
        ('abandonRequest',      Null), #AbandonRequest,
        ('extendedReq',         ExtendedRequest),
        ('extendedResp',        ExtendedResponse),
        ('intermediateResponse',Null), #IntermediateResponse },

    ]

class LDAPMessage(Sequence):
    _fields = [
        ('messageID', MessageID),
        ('protocolOp', ProtocolOp),
        ('controls', Controls, options(optional=True)),
    ]

