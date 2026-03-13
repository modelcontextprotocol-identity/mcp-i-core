export interface NewsSearchApiResponse {
  /** The type of search API result. The value is always news. */
  type: 'news';
  /** News search query string. */
  query: Query;
  /** The list of news results for the given query. */
  results: NewsResult[];
}

interface Query {
  /** The original query that was requested. */
  original: string;
  /** The altered query by the spellchecker. This is the query that is used to search if any. */
  altered?: string;
  /** The cleaned normalized query by the spellchecker. This is the query that is used to search if any. */
  cleaned?: string;
  /** Whether the spellchecker is enabled or disabled. */
  spellcheck_off?: boolean;
  /** The value is true if the lack of results is due to a strict safesearch setting. Adult content relevant to the query was found, but was blocked by safesearch. */
  show_strict_warning?: boolean;
}

export interface NewsResult {
  /** The type of news search API result. The value is always news_result. */
  type: 'news_result';
  /** The source URL of the news article. */
  url: string;
  /** The title of the news article. */
  title: string;
  /** The description for the news article. */
  description?: string;
  /** A human readable representation of the page age. */
  age?: string;
  /** The page age found from the source web page. */
  page_age?: string;
  /** The ISO date time when the page was last fetched. The format is YYYY-MM-DDTHH:MM:SSZ. */
  page_fetched?: string;
  /** Whether the result includes breaking news. */
  breaking?: boolean;
  /** The thumbnail for the news article. */
  thumbnail?: Thumbnail;
  /** Aggregated information on the URL associated with the news search result. */
  meta_url?: MetaUrl;
  /** A list of extra alternate snippets for the news search result. */
  extra_snippets?: string[];
}

interface Thumbnail {
  /** The served URL of the thumbnail associated with the news article. */
  src: string;
  /** The original URL of the thumbnail associated with the news article. */
  original?: string;
}

interface MetaUrl {
  /** The protocol scheme extracted from the URL. */
  scheme?: string;
  /** The network location part extracted from the URL. */
  netloc?: string;
  /** The lowercased domain name extracted from the URL. */
  hostname?: string;
  /** The favicon used for the URL. */
  favicon?: string;
  /** The hierarchical path of the URL useful as a display string. */
  path?: string;
}
