const { TelegramClient } = require("telegram");
const { StringSession } = require("telegram/sessions");
const input = require("input"); // npm install input for input prompts

const apiId = '29086040'; // Replace with your Telegram API ID
const apiHash = '56476bcf75ef0b9340f2dec21ea5cb12'; // Replace with your Telegram API Hash

const stringSession = new StringSession(""); // Empty session for the first run

(async () => {
    console.log("Loading interactive example...");
    const client = new TelegramClient(stringSession, apiId, apiHash, {
        connectionRetries: 5,
    });
    await client.start({
        phoneNumber: async () => await input.text("Enter your phone number: "),
        password: async () => await input.text("Enter your password (if 2FA is enabled): "),
        phoneCode: async () => await input.text("Enter the code you received: "),
        onError: (err) => console.log(err),
    });
    console.log("You are now connected.");
    console.log("Your session string:", client.session.save());
    await client.disconnect();
})();
