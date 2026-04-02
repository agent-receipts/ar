import type { PassThrough } from "node:stream";

/**
 * Read a single newline-delimited line from a stream.
 * Times out after 5 seconds.
 */
export function readLine(stream: PassThrough): Promise<string> {
	return new Promise((resolve, reject) => {
		let buffer = "";
		const timer = setTimeout(
			() => reject(new Error("Timeout waiting for line")),
			5000,
		);
		const onData = (chunk: Buffer) => {
			buffer += chunk.toString();
			const newlineIdx = buffer.indexOf("\n");
			if (newlineIdx !== -1) {
				clearTimeout(timer);
				stream.off("data", onData);
				resolve(buffer.slice(0, newlineIdx));
			}
		};
		stream.on("data", onData);
	});
}
