package org.dstadler.tika.fuzz;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.apache.tika.Tika;
import org.apache.tika.exception.TikaException;
import org.apache.tika.extractor.EmbeddedDocumentExtractor;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.sax.BodyContentHandler;
import org.apache.tika.metadata.Metadata;



public class FuzzPDFParser {
	private static final Tika tika = new Tika();

    private static class ImageExtractor implements EmbeddedDocumentExtractor {
        public ImageExtractor(String outputDir) {}
        @Override
        public boolean shouldParseEmbedded(Metadata metadata) {
            // Only parse embedded JPEG images
            String mimeType = metadata.get(Metadata.CONTENT_TYPE);
            return "image/jpeg".equalsIgnoreCase(mimeType);
        }
        @Override
        public void parseEmbedded(InputStream stream, org.xml.sax.ContentHandler handler, Metadata metadata, boolean outputHtml) throws IOException {
            throw new RuntimeException("That's an embedded JPEG!");
        };
    }

	public static void fuzzerTestOneInput(byte[] data) {
        // // force pdf header
        // if (data.length < 5 || data[0] != '%' || data[1] != 'P' || data[2] != 'D' || data[3] != 'F' || data[4] != '-') {
        //     return;
        // }

		try (InputStream is = new ByteArrayInputStream(data)) {
            // throw new RuntimeException("That's a PDF!");
            String mimeType = tika.detect(is);
            if (mimeType.equals("application/pdf")) {
                // reset the InputStream since tika.detect() may have read from it
                is.reset();

                BodyContentHandler handler = new BodyContentHandler();
                ParseContext context = new ParseContext();
                Metadata metadata = new Metadata();

                // set our custom embedded document extractor
                context.set(EmbeddedDocumentExtractor.class, new ImageExtractor("/tmp"));

                tika.getParser().parse(is, handler, metadata, context);
            }
		} catch (IOException | IllegalArgumentException e) {
			// expected from tika.detect
		} catch (TikaException e) {
            // expected from tika.parse
        } catch (Exception e) {
            // Any unexpected exceptions are rethrown
            throw new RuntimeException("Unexpected exception during parsing", e);
        }
	}
}

// tika-parser