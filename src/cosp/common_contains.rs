use super::hash;
pub fn contains_banned_name(text: &str) -> bool {
    const PINS: &[(usize, &str)] = &[
        (
            7,
            "21acb73a915f047af8b30af7b967133e022491b0efd6552029aa43f87988a83e",
        ),
        (
            7,
            "ec6f049478046f72becb006a2339202eae93911281dd610a7c869adec1ba3297",
        ),
        (
            9,
            "795b104abe3e4134960ca245ded0e617f162c751209347b7f003bc35e062f43e",
        ),
    ];
    let folded = text.to_lowercase();
    PINS.iter().any(|(width, digest)| {
        folded
            .as_bytes()
            .windows(*width)
            .any(|b| hash(b) == *digest)
    })
}
