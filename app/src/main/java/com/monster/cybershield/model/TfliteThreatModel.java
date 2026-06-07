package com.monster.cybershield.model;

import android.content.Context;
import android.content.res.AssetFileDescriptor;

import com.monster.cybershield.core.SecurityUpdateStore;

import org.tensorflow.lite.Interpreter;

import java.io.File;
import java.io.FileInputStream;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.util.HashMap;
import java.util.Map;

public final class TfliteThreatModel implements AutoCloseable {
    private final ModelSpec spec;
    private final Interpreter interpreter;
    private final boolean accelerated;

    public TfliteThreatModel(Context context, ModelSpec spec) {
        this.spec = spec;
        Interpreter loaded;
        boolean acceleratedLoad;
        File activeModel = new SecurityUpdateStore(context).activeModelIfPresent(spec.id);
        try {
            loaded = new Interpreter(loadModel(context, spec.asset, activeModel), options(true));
            acceleratedLoad = true;
        } catch (Throwable acceleratedError) {
            try {
                loaded = new Interpreter(loadModel(context, spec.asset, activeModel), options(false));
                acceleratedLoad = false;
            } catch (Throwable cpuError) {
                if (activeModel != null) {
                    try {
                        loaded = new Interpreter(loadAssetModel(context, spec.asset), options(false));
                        acceleratedLoad = false;
                    } catch (Throwable fallbackError) {
                        throw loadFailure(spec, acceleratedError, cpuError, fallbackError);
                    }
                } else {
                    throw loadFailure(spec, acceleratedError, cpuError, null);
                }
            }
        }
        this.interpreter = loaded;
        this.accelerated = acceleratedLoad;
    }

    public ThreatScore run(float[] features) {
        if (features.length != spec.inputSize) {
            throw new IllegalArgumentException("Feature size for " + spec.id + " must be " + spec.inputSize);
        }
        float[][] input = new float[][]{features};
        Map<Integer, Object> outputs = new HashMap<>();
        int outputCount = interpreter.getOutputTensorCount();
        for (int i = 0; i < outputCount; i++) {
            int[] shape = interpreter.getOutputTensor(i).shape();
            int width = shape.length > 1 ? shape[1] : 1;
            outputs.put(i, new float[1][width]);
        }
        interpreter.runForMultipleInputsOutputs(new Object[]{input}, outputs);

        float risk = 0f;
        float confidence = 0f;
        for (int i = 0; i < outputCount; i++) {
            float[][] value = (float[][]) outputs.get(i);
            if (value[0].length == 1) {
                risk = Math.max(risk, value[0][0]);
                confidence = Math.max(confidence, value[0][0]);
            } else {
                for (float v : value[0]) {
                    confidence = Math.max(confidence, v);
                }
            }
        }
        return new ThreatScore(spec.id, spec.title, risk, confidence, risk >= spec.threshold, spec.threshold);
    }

    public boolean isAccelerated() {
        return accelerated;
    }

    @Override
    public void close() {
        interpreter.close();
    }

    private static IllegalStateException loadFailure(ModelSpec spec, Throwable acceleratedError, Throwable cpuError, Throwable fallbackError) {
        String message = "Could not load TFLite model: " + spec.id
                + " | accelerated=" + describe(acceleratedError)
                + " | cpu=" + describe(cpuError);
        if (fallbackError != null) {
            message += " | assetFallback=" + describe(fallbackError);
        }
        return new IllegalStateException(message, fallbackError == null ? cpuError : fallbackError);
    }

    private static MappedByteBuffer loadModel(Context context, String assetPath, File activeModel) throws Exception {
        if (activeModel != null && activeModel.isFile() && activeModel.length() > 0) {
            try (FileInputStream input = new FileInputStream(activeModel);
                 FileChannel channel = input.getChannel()) {
                return channel.map(FileChannel.MapMode.READ_ONLY, 0, channel.size());
            }
        }
        return loadAssetModel(context, assetPath);
    }

    private static MappedByteBuffer loadAssetModel(Context context, String assetPath) throws Exception {
        try (AssetFileDescriptor descriptor = context.getAssets().openFd(assetPath);
             FileInputStream input = new FileInputStream(descriptor.getFileDescriptor());
             FileChannel channel = input.getChannel()) {
            return channel.map(FileChannel.MapMode.READ_ONLY, descriptor.getStartOffset(), descriptor.getDeclaredLength());
        }
    }

    private static Interpreter.Options options(boolean useXnnpack) {
        Interpreter.Options options = new Interpreter.Options();
        options.setNumThreads(2);
        options.setUseXNNPACK(useXnnpack);
        return options;
    }

    private static String describe(Throwable throwable) {
        StringBuilder builder = new StringBuilder();
        Throwable current = throwable;
        while (current != null) {
            if (builder.length() > 0) {
                builder.append(" <- ");
            }
            builder.append(current.getClass().getSimpleName()).append(": ").append(current.getMessage());
            current = current.getCause();
        }
        return builder.toString();
    }
}
