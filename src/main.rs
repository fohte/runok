fn main() {
    println!("Hello, world!");
}

#[cfg(test)]
mod tests {
    use rstest::rstest;

    #[rstest]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
