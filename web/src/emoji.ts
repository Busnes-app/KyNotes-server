/**
 * When ':' opens the emoji menu: only as the start of a word (start of the text or after
 * whitespace), so "due:" or "10:30" never does, and only once two letters follow it.
 */
export const emojiTriggerStartsWord = (textBefore: string) => textBefore === "" || /\s$/u.test(textBefore);
export const emojiQueryReady = (query: string) => /^\p{L}{2}/u.test(query);
