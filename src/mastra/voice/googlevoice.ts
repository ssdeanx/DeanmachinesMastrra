/**
 * Rich Google Voice implementation for Mastra
 *
 * This module provides text-to-speech and speech-to-text capabilities
 * using Google Cloud services with the Mastra voice interface.
 */

import { CompositeVoice, MastraVoice } from "@mastra/core/voice";
import { GoogleVoice } from "@mastra/voice-google";
import { allToolsMap } from "../tools";

/**
 * Interface for Google voice configuration options
 */
export interface GoogleVoiceConfig {
  /** Google Cloud API key or path to credentials JSON */
  apiKey?: string;
  /** Default voice name for TTS (e.g. "en-US-Wavenet-D") */
  speaker?: string;
  /** Model name for TTS */
  ttsModel?: string;
  /** Model name for STT */
  sttModel?: string;
}

/**
 * Create a Google voice provider with the specified configuration
 *
 * @param config - Configuration options for the Google voice provider
 * @returns Configured Google voice provider instance
 * @throws Error if required environment variables are missing
 */
export function createGoogleVoice({
  apiKey,
  speaker = "en-US-Wavenet-D",
  ttsModel = "default",
  sttModel = "default",
}: GoogleVoiceConfig = {}): MastraVoice {
  const key = apiKey || process.env.GOOGLE_API_KEY;
  if (!key) {
    throw new Error(
      "GoogleVoice requires an API key—set GOOGLE_API_KEY or pass apiKey"
    );
  }

  const speechModel = { apiKey: key, model: ttsModel };
  const listeningModel = { apiKey: key, model: sttModel };

  // instantiate low‑level GoogleVoice (only known props)
  const provider = new GoogleVoice({ speechModel, listeningModel, speaker });

  // composite gives you .speak(), .listen(), .getSpeakers(), .send(), .answer(), .on(), .off(), .close()
  const voice = new CompositeVoice({ speakProvider: provider, listenProvider: provider });

  // inject all of your Agent tools into the voice context
// auto‑add your Agent tools into the voice context
voice.addTools(Object.fromEntries(allToolsMap.entries()));
  // add any global voice instructions
  voice.addInstructions(
    "You are the DeanMachines AI assistant. Respond vocally and use your tools to help."
  );

  return voice;
}
