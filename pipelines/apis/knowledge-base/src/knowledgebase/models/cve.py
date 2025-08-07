
import datetime as dt
from datetime import datetime
import re
from neomodel import StructuredNode, RelationshipTo, RelationshipFrom, StructuredRel, Relationship
from neomodel import StringProperty, IntegerProperty, BooleanProperty, DateProperty, DateTimeFormatProperty, ArrayProperty, JSONProperty, FloatProperty
from neomodel import ZeroOrMore, OneOrMore, One, ZeroOrOne
import neomodel
import dateutil.parser

from ..node_update_hooks import node_updated, register_for_node_update
from .generic import Reference

import numpy as np


def DROP_KEY(o, key, optional=False):
    if not optional or key in o:
        del o[key]

def _parse_date(date):
    try:
        return dateutil.parser.isoparse(date)
    except ValueError:
        try:
            return dateutil.parser.isoparse(date + 'T00:00:00.000Z')
        except ValueError:
            return dateutil.parser.parse(date)

def parse_date(date):
    res = _parse_date(date)
    if res.tzinfo is None:
        res = res.replace(tzinfo=dt.timezone.utc)
    return res

def merge_dates(date1, date2):
    if date1 is None:
        return date2
    if date2 is None:
        return date1
    if date1.tzinfo is None:
        date1 = date1.replace(tzinfo=dt.timezone.utc)
    if date2.tzinfo is None:
        date2 = date2.replace(tzinfo=dt.timezone.utc)
    assert date1.year == date2.year and date1.month == date2.month and date1.day == date2.day, f'{date1=} != {date2=}'
    return max(date1, date2)

def parse_lang(lang):
    lang = {
        'eng': 'en',
    }.get(lang, lang)
    assert lang == 'en'
    return lang

VALID_TAG_REFERENCES = [
    "broken-link",
    "exploit",
    "government-resource",
    "issue-tracking",
    "mailing-list",
    "media-coverage",
    "mitigation",
    "patch",
    "permissions-required",
    "product",
    "related",
    "release-notes",
    "signature",
    "technical-description",
    "third-party-advisory",
    "vdb-entry",
    "vendor-advisory",
    "x_csaf",
    "x_redhatRef",
    "x_refsource_AIXAPAR",
    "x_refsource_ALLAIRE",
    "x_refsource_APPLE",
    "x_refsource_ATSTAKE",
    "x_refsource_AUSCERT",
    "x_refsource_BEA",
    "x_refsource_BID",
    "x_refsource_BINDVIEW",
    "x_refsource_BUGTRAQ",
    "x_refsource_CALDERA",
    "x_refsource_CERT",
    "x_refsource_CERT-VN",
    "x_refsource_CHECKPOINT",
    "x_refsource_CIAC",
    "x_refsource_CISCO",
    "x_refsource_COMPAQ",
    "x_refsource_CONECTIVA",
    "x_refsource_CONFIRM",
    "x_refsource_DEBIAN",
    "x_refsource_EEYE",
    "x_refsource_ENGARDE",
    "x_refsource_ERS",
    "x_refsource_EXPLOIT-DB",
    "x_refsource_FARMERVENEMA",
    "x_refsource_FEDORA",
    "x_refsource_FREEBSD",
    "x_refsource_FRSIRT",
    "x_refsource_FULLDISC",
    "x_refsource_GENTOO",
    "x_refsource_HP",
    "x_refsource_HPBUG",
    "x_refsource_IBM",
    "x_refsource_IDEFENSE",
    "x_refsource_IMMUNIX",
    "x_refsource_ISS",
    "x_refsource_JVN",
    "x_refsource_JVNDB",
    "x_refsource_L0PHT",
    "x_refsource_MANDRAKE",
    "x_refsource_MANDRIVA",
    "x_refsource_MISC",
    "x_refsource_MLIST",
    "x_refsource_MS",
    "x_refsource_MSKB",
    "x_refsource_NAI",
    "x_refsource_NETBSD",
    "x_refsource_NTBUGTRAQ",
    "x_refsource_OPENBSD",
    "x_refsource_OPENPKG",
    "x_refsource_OSVDB",
    "x_refsource_OVAL",
    "x_refsource_REDHAT",
    "x_refsource_SCO",
    "x_refsource_SECTRACK",
    "x_refsource_SECUNIA",
    "x_refsource_SF-INCIDENTS",
    "x_refsource_SGI",
    "x_refsource_SLACKWARE",
    "x_refsource_SREASON",
    "x_refsource_SREASONRES",
    "x_refsource_SUN",
    "x_refsource_SUNALERT",
    "x_refsource_SUNBUG",
    "x_refsource_SUSE",
    "x_refsource_TRUSTIX",
    "x_refsource_TURBO",
    "x_refsource_UBUNTU",
    "x_refsource_VIM",
    "x_refsource_VULN-DEV",
    "x_refsource_VULNWATCH",
    "x_refsource_VUPEN",
    "x_refsource_WIN2KSEC",
    "x_refsource_XF",
    "x_refsource_upstream_fix",
    "x_reporter",
    "x_research-advisory",
]

class CNA(StructuredNode):
    identifier = StringProperty(unique_index=True, required=True)

class CWE(StructuredNode):
    identifier = IntegerProperty(unique_index=True, required=True)
    name = StringProperty()
    status = StringProperty(choices={
        'Stable': 'Stable',
        'Draft': 'Draft',
        'Incomplete': 'Incomplete',
    })

    description = StringProperty()
    extended_description = StringProperty()

    alternate_terms = ArrayProperty(JSONProperty())

    notes = ArrayProperty(StringProperty())
    detection_methods = ArrayProperty(StringProperty())
    potential_mitigations = ArrayProperty(StringProperty())
    common_consequences = ArrayProperty(StringProperty())
    applicable_platforms = ArrayProperty(StringProperty())
    modes_of_introduction = ArrayProperty(StringProperty())
    observed_examples = ArrayProperty(StringProperty())

def parse_cwe_dict_list(s):
    return s.split('::')[1:-1]


def parse_cwe_record(o) -> CWE:
    assert 'CWE-ID' in o

    obj = {
        'identifier': o['CWE-ID'],
    }
    obj['name'] = o.get('Name', None)
    obj['status'] = o.get('Status', None)
    obj['description'] = o.get('Description', None)
    obj['extended_description'] = o.get('Extended Description', None)
    obj['alternate_terms'] = parse_cwe_dict_list(o.get('Alternate Terms', None))
    obj['notes'] = parse_cwe_dict_list(o.get('Notes', None))
    obj['detection_methods'] = parse_cwe_dict_list(o.get('Detection Methods', None))
    obj['potential_mitigations'] = parse_cwe_dict_list(o.get('Potential Mitigations', None))
    obj['common_consequences'] = parse_cwe_dict_list(o.get('Common Consequences', None))
    obj['applicable_platforms'] = parse_cwe_dict_list(o.get('Applicable Platforms', None))
    obj['modes_of_introduction'] = parse_cwe_dict_list(o.get('Modes Of Introduction', None))
    obj['observed_examples'] = parse_cwe_dict_list(o.get('Observed Examples', None))

    cwe = CWE.get_or_create(
        obj
    )[0].save()
    return cwe


class CVEReference(StructuredRel):
    name = StringProperty(),
    tags = ArrayProperty(StringProperty(choices={v: v for v in VALID_TAG_REFERENCES}))

class ProblemType(StructuredNode):
    type = StringProperty(required=True, choices={
        'CWE': 'CWE',
        'text': 'text',
    })
    language = StringProperty(required=True, choices={
        'en': 'en',
    })
    description = StringProperty()
    cwe = RelationshipTo('CWE', 'ASSIGNED_CWE')

class Assigner(StructuredNode):
    identifier = StringProperty(unique_index=True, required=True)
    short_name = StringProperty(required=True)

class Product(StructuredNode):
    product = StringProperty(unique_index=True, required=True)
    vendor = StringProperty(unique_index=True, required=True)

class AffectedBy(StructuredRel):
    affected_versions = JSONProperty()

class CVE(StructuredNode):
    identifier = StringProperty(unique_index=True, required=True)
    state = StringProperty(choices={
        'PUBLISHED': 'PUBLISHED',
        'REJECTED': 'REJECTED',
    }, required=True)

    datePublished = DateTimeFormatProperty(format='%Y-%m-%dT%H:%M:%S.%fZ')
    dateReserved = DateTimeFormatProperty(format='%Y-%m-%dT%H:%M:%S.%fZ')
    dateUpdated = DateTimeFormatProperty(format='%Y-%m-%dT%H:%M:%S.%fZ')
    dateAssigned = DateTimeFormatProperty(format='%Y-%m-%dT%H:%M:%S.%fZ')

    datePublic = DateTimeFormatProperty(format='%Y-%m-%dT%H:%M:%S.%fZ')
    descriptions = ArrayProperty(StringProperty())
    title = StringProperty()
    workarounds = ArrayProperty(StringProperty())
    solutions = ArrayProperty(StringProperty())

    references = Relationship('Reference', 'REFERENCE', model=CVEReference)

    assigner = Relationship('Assigner', 'ASSIGNED_BY')
    cwes = Relationship('CWE', 'CWE')
    cwes_referenced = Relationship('CWE', 'CWE_REFERENCED')
    problem_types = Relationship('ProblemType', 'PROBLEM_TYPE')

    products = Relationship('Product', 'AFFECTS', model=AffectedBy)


    def add_v4_cve_data_meta(self, meta):
        cve_id = meta.pop('ID', None)
        assigner = meta.pop('ASSIGNER', None)
        state = meta.pop('STATE', None)
        assert state == 'PUBLIC'

        if 'DATE_PUBLIC' in meta:
            datePublic = meta.pop('DATE_PUBLIC')
            datePublic = parse_date(datePublic)
            self.datePublic = merge_dates(self.datePublic, datePublic)
        if 'DATE_ASSIGNED' in meta:
            dateAssigned = meta.pop('DATE_ASSIGNED')
            dateAssigned = parse_date(dateAssigned)
            self.dateAssigned = merge_dates(self.dateAssigned, dateAssigned)
        if 'DATE_REQUESTED' in meta:
            dateRequested = meta.pop('DATE_REQUESTED')
            dateRequested = parse_date(dateRequested)
            self.dateReserved = merge_dates(self.dateReserved, dateRequested)

        if 'TITLE' in meta:
            title = meta.pop('TITLE')
            assert not self.title or self.title == title
            self.title = title

        DROP_KEY(meta, 'REQUESTER', optional=True) # don't see what we could use this for

        assert self.identifier == cve_id
        assert not meta, f'Unexpected keys in CVE_data_meta: {meta.keys()}'

    def add_v4_references(self, references):
        for reference in references:
            url = reference.pop('url')
            name = reference.pop('name')
            refsource = reference.pop('refsource')
            refsource_tag = 'x_refsource_' + refsource
            assert not reference, f'Unexpected keys in reference: {reference.keys()}'

            ref = Reference.get_or_create(
                {
                    'url': url,
                }
            )[0].save()
            ref = node_updated(ref)

            self.references.connect(ref, {'name': name, 'tags': [refsource_tag]})

    def add_v4_affected(self, affected):
        DROP_KEY(affected, 'vendor') # TODO: handle this

        assert not affected, f'Unexpected keys in affected: {affected.keys()}'

    def add_v4_description(self, description):
        description_data = description.pop('description_data')
        for d in description_data:
            lang = d.pop('lang')
            value = d.pop('value')
            if value == 'n/a':
                continue
            assert lang == 'eng'
            assert not d, f'Unexpected keys in description_data: {d.keys()}'
            # assert value in self.descriptions, f'v4 Description {value=} not in {self.descriptions=}'
            # we assume the v5 description is more up to date

        assert not description, f'Unexpected keys in description: {description.keys()}'


    def add_v4_problemtype_data(self, problemtype_data):
        for problem_type in problemtype_data.pop('problemtype_data'):
            for description in problem_type.pop('description'):
                value = description.pop('value')
                language = parse_lang(description.pop('lang'))
                if value == 'n/a':
                    continue

                assert language == 'en'
                assert not description, f'Unexpected keys in description: {description.keys()}'

                # find the CWE from the description
                if match := CWE_REGEX.search(value):
                    cwe = CWE.get_or_create(
                        {
                            'identifier': int(match.group(1)),
                        }
                    )[0].save()
                    cwe = node_updated(cwe)
                    self.cwes.connect(cwe)
            assert not problem_type, f'Unexpected keys in problem_type: {problem_type.keys()}'
        assert not problemtype_data, f'Unexpected keys in problemtype_data: {problemtype_data.keys()}'


def parse_cve_record_v5_json(o) -> CVE:
    parsed = {}
    parsed['dataType'] = o.pop('dataType')
    parsed['dataVersion'] = o.pop('dataVersion')

    meta = o.pop('cveMetadata')
    parsed['cveMetadata'] = meta

    cve = CVE.get_or_create(
        {
            'identifier': meta.pop('cveId'),
            'state': meta.pop('state'),
            'datePublished': parse_date(meta.pop('datePublished')),
            'dateReserved': parse_date(meta.pop('dateReserved')),
            'dateUpdated': parse_date(meta.pop('dateUpdated'))
        }
    )[0].save()
    parsed['cve'] = cve

    cve.assigner.connect(
        node_updated(Assigner.get_or_create(
            {
                'identifier': meta.pop('assignerOrgId'),
                'short_name': meta.pop('assignerShortName')
            }
        )[0].save())
    )
    assert not meta, f'Unexpected keys in cveMetadata: {meta.keys()}'

    containers = o.pop('containers')
    cna = containers.pop('cna')
    assert not containers, f'Unexpected keys in containers: {containers.keys()}'

    if providerMetadata := cna.pop('providerMetadata', None):
        if dateUpdated := providerMetadata.pop('dateUpdated', None):
            dateUpdated = parse_date(dateUpdated)
            cve.dateUpdated = merge_dates(cve.dateUpdated, dateUpdated)

        orgId = providerMetadata.pop('orgId')
        shortName = providerMetadata.pop('shortName')
        cve.assigner.connect(
            node_updated(Assigner.get_or_create(
                {
                    'identifier': orgId,
                    'short_name': shortName
                }
            )[0].save())
        )
        assert not providerMetadata, f'Unexpected keys in providerMetadata: {providerMetadata.keys()}'

    if datePublic := cna.pop('datePublic', None):
        cve.datePublic = parse_date(datePublic)

    if dateAssigned := cna.pop('dateAssigned', None):
        cve.dateAssigned = parse_date(dateAssigned)

    if title := cna.pop('title', None):
        cve.title = title

    if descriptions := cna.pop('descriptions', None):
        cve.descriptions = [
            d['value'] for d in descriptions
        ]
    if solutions := cna.pop('solutions', None):
        solns = []
        for solution in solutions:
            lang = parse_lang(solution.pop('lang'))
            value = solution.pop('value')
            DROP_KEY(solution, 'supportingMedia', optional=True)
            if value == 'n/a':
                continue
            solns.append(value)
            assert lang == 'en'
            assert not solution, f'Unexpected keys in solution: {solution.keys()}'
        cve.solutions = solns

    if workarounds := cna.pop('workarounds', None):
        wrk = []
        for workaround in workarounds:
            lang = parse_lang(workaround.pop('lang'))
            value = workaround.pop('value')
            if value == 'n/a':
                continue
            wrk.append(value)
            assert lang == 'en'
            assert not workaround, f'Unexpected keys in workaround: {workaround.keys()}'
        cve.workarounds = wrk



    for reference in cna.pop('references'):
        ref = Reference.get_or_create(
            {'url': reference['url']}
        )[0].save()
        ref = node_updated(ref)

        cve.references.connect(ref, {'name': reference.get('name'), 'tags': reference.get('tags', [])})

    for problem_type in cna.pop('problemTypes', []):
        assert len(problem_type['descriptions']) == 1
        desc = problem_type['descriptions'][0]
        if desc['type'] == 'CWE':
            cwe = CWE.get_or_create(
                {
                    'identifier': int(desc['cweId'].split('-')[1]),
                }
            )[0].save()
            cwe = node_updated(cwe)
            cve.cwes.connect(cwe)
            problem_type = ProblemType.get_or_create(
                {
                    'type': 'CWE',
                    'cweId': desc['cweId'],
                    'language': desc['lang'],
                    'description': desc['description'],
                }
            )[0].save()
            problem_type = node_updated(problem_type)
            cve.problem_types.connect(problem_type)
            problem_type.cwe.connect(cwe)

        else:
            if desc['description'] == 'n/a':
                continue
            pt = ProblemType.get_or_create(
                {
                    'type': desc['type'],
                    'language': desc['lang'],
                    'description': desc['description'],
                }
            )[0].save()
            pt = node_updated(pt)
            cve.problem_types.connect(pt)

    for affected in cna.pop('affected', []):
        assert 'vendor' in affected
        assert 'product' in affected
        assert 'versions' in affected
        if affected['vendor'] == 'n/a' and affected['product'] == 'n/a':
            continue

        product = Product.get_or_create(
            {
                'product': affected['product'],
                'vendor': affected['vendor']
            }
        )[0].save()
        product = node_updated(product)

        cve.products.connect(product, {'affected_versions': affected['versions']})

    if legacy_v4_record := cna.pop('x_legacyV4Record', None):
        parsed['legacy_v4_record'] = legacy_v4_record
        parse_v4_data(cve, legacy_v4_record)

    DROP_KEY(cna, 'metrics', optional=True)
    DROP_KEY(cna, 'credits', optional=True)
    DROP_KEY(cna, 'timeline', optional=True)    # TODO: this is potentially interesting
    DROP_KEY(cna, 'source', optional=True)      # TODO: this is potentially interesting
    DROP_KEY(cna, 'impacts', optional=True)     # TODO: this is potentially interesting, CAPEC capabilities
    DROP_KEY(cna, 'x_generator', optional=True)

    assert not cna, f'Unexpected keys in cna: {cna.keys()}'
    assert not o, f'Unexpected keys in v5 data: {o.keys()}'

    return cve.save()

CWE_REGEX = re.compile(r'CWE-(\d+)')

FIRST = True
def parse_v4_data(cve: CVE, o) -> CVE:
    assert o.pop('data_format') == 'MITRE'
    assert o.pop('data_type') == 'CVE'
    assert o.pop('data_version') == '4.0'
    CVE_data_meta = cve.add_v4_cve_data_meta(o.pop('CVE_data_meta'))

    problemtype_data = o.pop('problemtype', None)
    cve.add_v4_problemtype_data(problemtype_data)
    refs = o.pop('references')
    references = refs.pop('reference_data')
    assert not refs, f'Unexpected keys in references: {refs.keys()}'
    cve.add_v4_references(references)

    affected = o.pop('affects', None)
    cve.add_v4_affected(affected)

    description = o.pop('description', None)
    cve.add_v4_description(description)

    DROP_KEY(o, 'impact', optional=True)


    DROP_KEY(o, 'credit', optional=True)
    DROP_KEY(o, 'generator', optional=True)
    DROP_KEY(o, 'source', optional=True) # TODO: this is potentially interesting

    assert not o, f'Unexpected keys in v4 data: {o.keys()}'

    return cve.save()
