package org.dstadler.tika.fuzz;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.io.File;

import java.net.URLClassLoader;
import java.net.URL;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.google.common.util.concurrent.ExecutionError;

import org.apache.tika.Tika;
import org.apache.tika.exception.TikaException;
import org.apache.tika.TikaTest;
import org.apache.tika.config.TikaConfig;
import org.apache.tika.exception.TikaConfigException;
import org.apache.tika.extractor.ContainerExtractor;
import org.apache.tika.extractor.ParserContainerExtractor;
import org.apache.tika.io.TikaInputStream;
import org.apache.tika.metadata.Metadata;
import org.apache.tika.metadata.PDF;
import org.apache.tika.metadata.TikaCoreProperties;
import org.apache.tika.mime.MediaType;
import org.apache.tika.parser.AutoDetectParser;
import org.apache.tika.parser.ParseContext;
import org.apache.tika.parser.Parser;
import org.apache.tika.parser.RecursiveParserWrapper;
import org.apache.tika.parser.external.ExternalParser;
import org.apache.tika.parser.xml.XMLProfiler;
import org.apache.tika.sax.BasicContentHandlerFactory;
import org.apache.tika.sax.BasicContentHandlerFactory.HANDLER_TYPE;
import org.apache.tika.sax.RecursiveParserWrapperHandler;
import org.apache.tika.sax.ToXMLContentHandler;
import org.junit.jupiter.api.Test;

public class Fuzz extends TikaTest {
	// private static final Tika tika = new Tika();
	public static void fuzzerTestOneInput(FuzzedDataProvider data) {
		System.out.println("Classpath: " + System.getProperty("java.class.path"));
    try {
        new Fuzz().fuzz(data);
    } catch (IOException e) {
        System.err.println("IO Error in fuzzer: " + e.getMessage());
        e.printStackTrace();
    } catch (TikaException e) {
        System.err.println("Tika Error in fuzzer: " + e.getMessage());
        e.printStackTrace();
    } catch (Exception e) {
        System.err.println("Unexpected error in fuzzer: " + e.getMessage());
        e.printStackTrace();
    }
	}

	private void fuzz(FuzzedDataProvider input) throws IOException, TikaException, TikaConfigException {
		System.out.println("===============================================================");
		System.out.println(System.getProperty("java.class.path"));
		System.out.println("Hello World");
		// try to invoke various methods which parse documents/workbooks/slide-shows/...
		byte[] fileContent = input.consumeBytes(input.consumeInt(0, 1024 * 1024)); // Max 1MB
		File tempFile = null;
            // Create a temporary file
		try {
            tempFile = File.createTempFile("fuzz", ".pdf");
            
            // Write the fuzzed content to the temporary file
            try (FileOutputStream fos = new FileOutputStream(tempFile)) {
                fos.write(fileContent);
            }
			catch (IOException e) {
				e.printStackTrace();
			}

            // Parse the fuzzed PDF file

			List<Metadata> metadataList =
			getRecursiveMetadataFromFullPath(tempFile.getPath());
			assertEquals(1, metadataList.size());

			 try (InputStream is = getResourceAsStream(
                "/org/apache/tika/parser/pdf/tika-xml-profiler-config.xml")) {
            assertNotNull(is);
            TikaConfig tikaConfig = new TikaConfig(is);
            Parser p = new AutoDetectParser(tikaConfig);
			
			// InputStream stream = getResourceAsStream(tempFile.getPath());
            metadataList = getRecursiveMetadata(tempFile.toPath(), p, true);
            assertEquals(3, metadataList.size());
			

        }
        int xmlProfilers = 0;
        for (Metadata metadata : metadataList) {
            String[] parsedBy = metadata.getValues(TikaCoreProperties.TIKA_PARSED_BY);
            for (String s : parsedBy) {
                if (s.equals(XMLProfiler.class.getCanonicalName())) {
                    xmlProfilers++;
                }
            }
        }

        assertEquals(2, xmlProfilers);

        //check xmp first
        String[] uris = metadataList.get(1).getValues(XMLProfiler.ENTITY_URIS);
        String[] localNames = metadataList.get(1).getValues(XMLProfiler.ENTITY_LOCAL_NAMES);
        assertEquals(8, uris.length);
        assertEquals(uris.length, localNames.length);
        assertEquals("adobe:ns:meta/", uris[0]);
        assertEquals("CreateDate CreatorTool MetadataDate ModifyDate Thumbnails", localNames[2]);
        assertEquals("x:xmpmeta", metadataList.get(1).get(XMLProfiler.ROOT_ENTITY));

        //check xfa
        uris = metadataList.get(2).getValues(XMLProfiler.ENTITY_URIS);
        localNames = metadataList.get(2).getValues(XMLProfiler.ENTITY_LOCAL_NAMES);
        assertEquals(8, uris.length);
        assertEquals(uris.length, localNames.length);
        assertEquals("http://ns.adobe.com/xdp/", uris[1]);
        assertEquals("field form instanceManager subform value", localNames[5]);
        assertEquals("xdp:xdp", metadataList.get(2).get(XMLProfiler.ROOT_ENTITY));
		
		Parser parser = new AutoDetectParser();
		parser.parse(new ByteArrayInputStream(fileContent), new ToXMLContentHandler(), new Metadata(), new ParseContext());
		} catch (Exception e) {
			System.err.println("Error in fuzz: " + e.getMessage());
			e.printStackTrace();
		} finally {
			if (tempFile != null) {
				tempFile.delete();
			}
		}
	}
}
