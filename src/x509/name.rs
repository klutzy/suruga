use der::{Tag, FromTlv, DerResult, DerReader, ObjId};
use der::DerErrorKind::InvalidTag;

// TODO full of hacks. parse attribute correctly

pub type DirectoryString = String;

sequence!(struct AttributeTypeAndValue {
    attr_type: ObjId,
    attr_value: DirectoryString,
});

// TODO set_of macro
// SET SIZE (1..MAX) of AttributeTypeAndValue
#[derive(Debug)]
pub struct RelativeDistinguishedName {
    set: Vec<AttributeTypeAndValue>,
}

impl FromTlv for RelativeDistinguishedName {
    fn from_tlv(tag: Tag, value: &[u8]) -> DerResult<RelativeDistinguishedName> {
        match tag {
            Tag::Set => {
                let set_parser = DerReader::new(value);
                let value: RelativeDistinguishedName = try!(RelativeDistinguishedName::from_set(set_parser));
                Ok(value)
            }
            _ => return der_err!(InvalidTag, "unexpected tag: {:?}", tag),
        }
    }
}

impl RelativeDistinguishedName {
    fn from_set(mut parser: DerReader) -> DerResult<RelativeDistinguishedName> {
        let mut set = Vec::new();

        // TODO this currently throws error if nonunderstandable AttributeTypeAndValue is found.
        // is it okay? we certainly need data for deciding it..
        while !parser.is_eof() {
            // TODO check sortness
            let (tag, value) = try!(parser.next_tlv());
            let item: AttributeTypeAndValue = try!(FromTlv::from_tlv(tag, value));
            set.push(item);
        }

        Ok(RelativeDistinguishedName {
            set: set,
        })
    }
}

// Name ::= CHOICE { RdnSequence }
// RdnSequence ::= SEQUENCE OF RelativeDistinguishedName
sequence_of!(struct Name = RelativeDistinguishedName(0));
