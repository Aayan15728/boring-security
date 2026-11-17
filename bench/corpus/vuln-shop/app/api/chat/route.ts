import { NextResponse } from 'next/server'
import OpenAI from 'openai'

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY })

const SYSTEM_PROMPT = `You are Cobi, the shopping assistant for Cobalt Goods.
Help customers find products, explain shipping times and answer questions about returns.
Keep answers short and friendly.`

type ChatMessage = { role: 'user' | 'assistant'; content: string }

export async function POST(req: Request) {
  const { messages } = (await req.json()) as { messages: ChatMessage[] }

  if (!Array.isArray(messages) || messages.length === 0) {
    return NextResponse.json({ error: 'messages required' }, { status: 400 })
  }

  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'system', content: SYSTEM_PROMPT }, ...messages],
    temperature: 0.4,
  })

  return NextResponse.json({ reply: completion.choices[0]?.message?.content ?? '' })
}
