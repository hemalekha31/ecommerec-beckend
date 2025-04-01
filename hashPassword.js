const bcrypt = require("bcrypt");

const plainPassword = "testpassword"; // Change this to the password you want to hash

bcrypt.hash(plainPassword, 10).then((hashedPassword) => {
    console.log("Hashed Password:", hashedPassword);
});
