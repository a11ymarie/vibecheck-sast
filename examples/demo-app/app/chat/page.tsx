'use client'
// Demo app: deliberately insecure. Do not deploy.
import OpenAI from 'openai'
import {useState} from 'react'

const openai = new OpenAI({apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY, dangerouslyAllowBrowser: true})

export default function ChatPage() {
  const [reply, setReply] = useState('')
  async function send(message: string) {
    const res = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages: [{role: 'user', content: message}],
    })
    setReply(res.choices[0].message.content ?? '')
  }
  return <button onClick={() => send('Summarize my notes')}>{reply || 'Ask the assistant'}</button>
}
