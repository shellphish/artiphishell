package org.dstadler.tika.fuzz;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.tika.Tika;
import org.apache.tika.exception.TikaException;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.sax.BasicContentHandlerFactory;
import org.apache.tika.sax.BasicContentHandlerFactory.HANDLER_TYPE;
import org.apache.tika.parser.ParseContext;
import org.xml.sax.ContentHandler;
import org.xml.sax.SAXException;

public class Fuzz {
    private static final Tika tika = new Tika();

    public static void fuzzerTestOneInput(byte[] input) {
        try (InputStream str = new ByteArrayInputStream(input)) {
            // Detect the file type
            int partSize = input.length / 4;
			byte[][] parts = new byte[4][];
			for (int i = 0; i < 4; i++) {
				int start = i * partSize;
				int end = (i == 3) ? input.length : start + partSize;
				parts[i] = new byte[end - start];
				System.arraycopy(input, start, parts[i], 0, end - start);
			}
			for(byte[] part: parts){
            String detectedType = tika.detect(part);

            // Switch-case to handle different file formats
            switch (detectedType) {
                case "application/pdf":
                    evaluatePDF(part);
                    break;
                case "application/msword":
                case "application/vnd.openxmlformats-officedocument.wordprocessingml.document":
                    evaluateWord(part);
                    break;
                case "image/jpeg":
                    evaluateImage(part);
                    break;
                // Add more cases for other file types as needed
                default:
                    evaluateDefault(part);
                    break;
            }
        }
        } catch (IOException e) {
            // Ignore exceptions and continue
        }
    }

    private static void evaluatePDF(byte[] input) {
        try (InputStream is = new ByteArrayInputStream(input)) {
            // Create a ContentHandler using BasicContentHandlerFactory
            BasicContentHandlerFactory factory = new BasicContentHandlerFactory(HANDLER_TYPE.TEXT, -1);
            ContentHandler handler = factory.getNewContentHandler();

            // Parse the input stream with the handler
            Metadata metadata = new Metadata();
            ParseContext context = new ParseContext();
            tika.getParser().parse(is, handler, metadata, context);

            // Retrieve the content
            String content = handler.toString();

            // Perform any evaluation on the content
        } catch (IOException | TikaException | SAXException e) {
            // Ignore exceptions and continue
        }
    }

    private static void evaluateWord(byte[] input) {
        try (InputStream is = new ByteArrayInputStream(input)) {
            // Create a ContentHandler using BasicContentHandlerFactory
            BasicContentHandlerFactory factory = new BasicContentHandlerFactory(HANDLER_TYPE.TEXT, -1);
            ContentHandler handler = factory.getNewContentHandler();

            // Parse the input stream with the handler
            Metadata metadata = new Metadata();
            ParseContext context = new ParseContext();
            tika.getParser().parse(is, handler, metadata, context);

            // Retrieve the content
            String content = handler.toString();

            // Perform any evaluation on the content
        } catch (IOException | TikaException | SAXException e) {
            // Ignore exceptions and continue
        }
    }

    private static void evaluateImage(byte[] input) {
        try (InputStream is = new ByteArrayInputStream(input)) {
            // For images, we can extract metadata without using a content handler
            Metadata metadata = new Metadata();
            tika.parse(is, metadata);

            // Evaluate metadata (e.g., image dimensions, camera model)
            String width = metadata.get("tiff:ImageWidth");
            String height = metadata.get("tiff:ImageLength");
        } catch (IOException e) {
            // Ignore exceptions and continue
        }
    }

    private static void evaluateDefault(byte[] input) {
        try (InputStream is = new ByteArrayInputStream(input)) {
            // Create a ContentHandler using BasicContentHandlerFactory
            BasicContentHandlerFactory factory = new BasicContentHandlerFactory(HANDLER_TYPE.TEXT, -1);
            ContentHandler handler = factory.getNewContentHandler();

            // Parse the input stream with the handler
            Metadata metadata = new Metadata();
            ParseContext context = new ParseContext();
            tika.getParser().parse(is, handler, metadata, context);

            // Retrieve the content
            String content = handler.toString();

            // Perform any evaluation on the content
        } catch (IOException | TikaException | SAXException e) {
            // Ignore exceptions and continue
        }
    }
}
