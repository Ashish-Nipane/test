const ERROR_FIELDS = ["error", "errorMessage"];

export type NetworkErrorOptions = { response: Response; responseData: unknown };

export class NetworkError extends Error {
  response: Response;
  responseData: unknown;

  constructor(message: string, options: NetworkErrorOptions) {
    super(message);
    this.response = options.response;
    this.responseData = options.responseData;
  }
}

export async function fetchWithError(
  input: RequestInfo | URL,
  init?: RequestInit,
) {
  const response = await fetch(input, init);

  if (!response.ok) {
    const responseData = await parseResponse(response);
    const description = getNetworkErrorMessage(responseData)
    throw new NetworkError(description, {
      response,
      responseData,
    });
  }

  return response;
}

export async function parseResponse(response: Response): Promise<any> {
  if (!response.body) {
    return "";
  }

  const data = await response.text();

  try {
    return JSON.parse(data);
    // eslint-disable-next-line no-empty
  } catch (error) {}

  return data;
}


function getNetworkErrorMessage(data: unknown): string {
  if (typeof data !== "object" || data === null) {
    return "Unable to determine error message.";
  }

  for (const key of ERROR_FIELDS) {
    const value = (data as Record<string, unknown>)[key];

    if (typeof value === "string") {
      return value;
    }
  }

  return "Network response was not OK."
}