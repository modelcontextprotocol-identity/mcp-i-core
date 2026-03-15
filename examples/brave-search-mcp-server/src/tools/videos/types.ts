export interface VideoSearchApiResponse {
  /** The type of search API result. The value is always video. */
  type: 'videos';
  /** Video search query string. */
  query: Query;
  /** The list of video results for the given query. */
  results: VideoResult[];
  /** Additional information about the video search results. */
  extra: Extra;
}

interface Query {
  /** The original query that was requested. */
  original: string;
  /** The altered query by the spellchecker. This is the query that is used to search if any. */
  altered?: string;
  /** The cleaned noramlized query by the spellchecker. This is the query that is used to search if any. */
  cleaned?: string;
  /** Whether the spellchecker is enabled or disabled. */
  spellcheck_off?: boolean;
  /** The value is true if the lack of results is due to a strict safesearch setting. Adult content relevant to the query was found, but was blocked by safesearch. */
  show_strict_warning?: string;
}

interface Thumbnail {
  /** The served URL of the thumbnail associated with the video. */
  src: string;
  /** The original URL of the thumbnail associated with the video. */
  original?: string;
}

interface Profile {
  /** The name of the profile. */
  name: string;
  /** The long name of the profile. */
  long_name?: string;
  /** The original URL where the profile is available. */
  url: string;
  /** The served image URL representing the profile. */
  img?: string;
}

interface VideoData {
  /** A time string representing the duration of the video. */
  duration?: string;
  /** The number of views of the video. */
  views?: number;
  /** The creator of the video. */
  creator?: string;
  /** The publisher of the video. */
  publisher?: string;
  /** Whether the video requires a subscription. */
  requires_subscription?: boolean;
  /** A list of tags relevant to the video. */
  tags?: string[];
  /** A list of profiles associated with the video. */
  author?: Profile;
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

export interface VideoResult {
  /** The type of video search API result. The value is always video_result. */
  type: 'video_result';
  /** The source URL of the video. */
  url: string;
  /** The title of the video. */
  title: string;
  /** The description for the video. */
  description?: string;
  /** A human readable representation of the page age. */
  age?: string;
  /** The page age found from the source web page. */
  page_age?: string;
  /** The ISO date time when the page was last fetched. The format is YYYY-MM-DDTHH:MM:SSZ. */
  page_fetched?: string;
  /** The thumbnail for the video. */
  thumbnail?: Thumbnail;
  /** Metadata for the video. */
  video?: VideoData;
  /** Aggregated information on the URL associated with the video search result. */
  meta_url?: MetaUrl;
}

interface Extra {
  /** Indicates whether the video search results might contain offensive content. */
  might_be_offensive: boolean;
}
