use der::Time;

sequence!(struct Validity {
    not_before: Time,
    not_after: Time,
});
