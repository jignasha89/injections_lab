declare module 'openai' {
  interface ChatCompletionMessageParam {
    role: 'system' | 'user' | 'assistant';
    content: string;
  }

  interface ChatCompletionChoice {
    message: {
      content: string | null;
      role: string;
    };
  }

  interface ChatCompletion {
    choices: ChatCompletionChoice[];
  }

  export default class OpenAI {
    constructor(options?: { apiKey?: string; [key: string]: any });
    chat: {
      completions: {
        create(params: {
          model: string;
          messages: ChatCompletionMessageParam[];
          temperature?: number;
          max_tokens?: number;
          [key: string]: any;
        }): Promise<ChatCompletion>;
      };
    };
  }
}
