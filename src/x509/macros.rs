macro_rules! choice_tagged {
    (
        enum $choice_name:ident {
            $(
                [$cls:ident:$id:expr] $name:ident($($opts:tt)*): $t:ty,
            )+
        }
    ) => (
        #[derive(Debug)]
        pub enum $choice_name {
            $(
                $name($t),
            )+
        }

        impl FromTlv for $choice_name {
            fn from_tlv(tag: Tag, value: &[u8]) -> DerResult<$choice_name> {
                $(
                    if tag == ctx_sp!($cls, $id) {
                        let item: $t = choice_tagged_item!($t, tag, value, $($opts)*);
                        return Ok($choice_name::$name(item));
                    }
                )+
                return der_err!(InvalidVal, "unexpected choice tag: {:?}", tag);
            }
        }
    )
}

macro_rules! choice_tagged_item {
    ($t:ty, $tag:expr, $value:expr, IMPLICIT, $new_tag:path) => ({
        let choice_value: $t = try!(FromTlv::from_tlv($new_tag, $value));
        choice_value
    });
    ($t:ty, $tag:expr, $value:expr, EXPLICIT) => ({
        let mut exp_parser = DerReader::new($value);
        let (exp_tag, exp_value) = try!(exp_parser.next_tlv());
        let new_value: $t = try!(FromTlv::from_tlv(exp_tag, exp_value));
        new_value
    });
}
