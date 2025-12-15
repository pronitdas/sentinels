import { EventEmitter } from 'events';
import { FastifyReply } from 'fastify';
import { ScanStatus } from './db';

type ScanEventPayload = {
  type: 'status' | 'log';
  status?: ScanStatus;
  scanner?: string;
  message?: string;
  timestamp?: string;
};

const emitter = new EventEmitter();
// Allow unbounded listeners per scan ID to avoid warnings for multiple SSE subscribers
emitter.setMaxListeners(0);

export function emitScanEvent(scanId: string, payload: ScanEventPayload) {
  emitter.emit(scanId, payload);
}

export function streamScanEvents(reply: FastifyReply, scanId: string, initialEvent?: ScanEventPayload) {
  reply.raw.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    Connection: 'keep-alive',
  });

  const send = (payload: ScanEventPayload) => {
    reply.raw.write(`data: ${JSON.stringify(payload)}\n\n`);
  };

  if (initialEvent) {
    send(initialEvent);
  }

  const heartbeat = setInterval(() => {
    reply.raw.write(': keep-alive\n\n');
  }, 15000);

  const handler = (payload: ScanEventPayload) => send(payload);
  emitter.on(scanId, handler);

  reply.raw.on('close', () => {
    clearInterval(heartbeat);
    emitter.off(scanId, handler);
    reply.raw.end();
  });
}
