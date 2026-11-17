package org.netscope.ngfw;

import android.content.Context;
import android.content.Intent;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.speech.RecognitionListener;
import android.speech.RecognizerIntent;
import android.speech.SpeechRecognizer;
import java.util.ArrayList;
import java.util.Locale;
import java.util.function.Consumer;

/** One foreground utterance with Android's on-device recognizer. */
final class OnDeviceVoice {
    private final Handler main = new Handler(Looper.getMainLooper());
    private SpeechRecognizer recognizer;
    private Runnable timeout;

    static boolean available(Context context) {
        return Build.VERSION.SDK_INT >= 31 && SpeechRecognizer.isOnDeviceRecognitionAvailable(context);
    }

    boolean start(Context context, Locale language, Consumer<VoiceCommand> command, Runnable failure) {
        if (Build.VERSION.SDK_INT < 31 || !available(context)) return false;
        stop();
        try {
            SpeechRecognizer current = SpeechRecognizer.createOnDeviceSpeechRecognizer(context);
            recognizer = current;
            timeout = () -> {
                if (recognizer == current) {
                    stop();
                    failure.run();
                }
            };
            current.setRecognitionListener(new RecognitionListener() {
                @Override public void onResults(Bundle results) {
                    if (recognizer != current) return;
                    ArrayList<String> candidates = results.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION);
                    VoiceCommand parsed = candidates == null || candidates.isEmpty()
                        ? VoiceCommand.UNKNOWN : VoiceCommand.parse(candidates.get(0));
                    stop();
                    command.accept(parsed);
                }

                @Override public void onError(int error) {
                    if (recognizer != current) return;
                    stop();
                    failure.run();
                }

                @Override public void onReadyForSpeech(Bundle parameters) {}
                @Override public void onBeginningOfSpeech() {}
                @Override public void onRmsChanged(float rms) {}
                @Override public void onBufferReceived(byte[] buffer) {}
                @Override public void onEndOfSpeech() {}
                @Override public void onPartialResults(Bundle partial) {}
                @Override public void onEvent(int type, Bundle data) {}
            });
            Intent intent = new Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH)
                .putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
                .putExtra(RecognizerIntent.EXTRA_LANGUAGE, language.toLanguageTag())
                .putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 1)
                .putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, false);
            main.postDelayed(timeout, 8000);
            current.startListening(intent);
            return true;
        } catch (RuntimeException error) {
            stop();
            return false;
        }
    }

    void stop() {
        SpeechRecognizer current = recognizer;
        recognizer = null;
        if (timeout != null) {
            main.removeCallbacks(timeout);
            timeout = null;
        }
        if (current != null) current.destroy();
    }
}
