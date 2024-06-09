use passwords;

pub struct PasswordGenerator {
    generator: passwords::PasswordGenerator,
}

impl PasswordGenerator{
    pub fn new() -> PasswordGenerator {
        PasswordGenerator {
            generator: passwords::PasswordGenerator::new()
        }
    }

    pub fn generate_password(&self) {
        let pw = self.generator.generate_one().unwrap();
        println!("{}", pw);
    }

    // default 8
    pub fn set_length(&mut self, length: usize) {
        self.generator.length = length;
    }

    // default true
    pub fn toggle_numbers(&mut self) {
        self.generator.numbers = !self.generator.numbers;
    }

    // default false
    pub fn toggle_symbols(&mut self) {
        self.generator.symbols = !self.generator.symbols;
    }

    // default false
    pub fn toggle_uppercase(&mut self) {
        self.generator.uppercase_letters = !self.generator.uppercase_letters;
    }

    //default true
    pub fn toggle_lowercase(&mut self) {
        self.generator.lowercase_letters = !self.generator.lowercase_letters;
    }

    // default false
    pub fn toggle_spaces(&mut self) {
        self.generator.spaces = !self.generator.spaces;
    }

    // default false
    pub fn toggle_similar(&mut self) {
        self.generator.exclude_similar_characters = !self.generator.exclude_similar_characters;
    }

    // default false
    pub fn toggle_strict(&mut self) {
        self.generator.strict = !self.generator.strict;
    }

    pub fn print_settings(&self) {
        println!("Length: {}", self.generator.length);
        println!("Numbers: {}", self.generator.numbers);
        println!("Symbols: {}", self.generator.symbols);
        println!("Uppercase: {}", self.generator.uppercase_letters);
        println!("Lowercase: {}", self.generator.lowercase_letters);
        println!("Spaces: {}", self.generator.spaces);
        println!("Similar: {}", self.generator.exclude_similar_characters);
        println!("Strict: {}", self.generator.strict);
    }
}