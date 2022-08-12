// SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>
//
// SPDX-License-Identifier: Apache-2.0

package pgp.cert_d.cli;

import org.pgpainless.certificate_store.PGPainlessCertD;
import pgp.cert_d.BaseDirectoryProvider;
import pgp.cert_d.cli.commands.Export;
import pgp.cert_d.cli.commands.Find;
import pgp.cert_d.cli.commands.Get;
import pgp.cert_d.cli.commands.Insert;
import pgp.cert_d.cli.commands.Import;
import pgp.cert_d.cli.commands.List;
import pgp.cert_d.cli.commands.Setup;
import pgp.cert_d.jdbc.sqlite.DatabaseSubkeyLookupFactory;
import pgp.certificate_store.exception.NotAStoreException;
import picocli.CommandLine;

import java.io.File;
import java.sql.SQLException;

@CommandLine.Command(
        name = "certificate-store",
        resourceBundle = "msg_pgp-cert-d",
        subcommands = {
                CommandLine.HelpCommand.class,
                Export.class,
                Insert.class,
                Import.class,
                Get.class,
                Setup.class,
                List.class,
                Find.class
        }
)
public class PGPCertDCli {

    @CommandLine.Option(names = {"-s", "--store"}, paramLabel = "DIRECTORY",
            scope = CommandLine.ScopeType.INHERIT)
    File baseDirectory;

    private static PGPainlessCertD certificateDirectory;

    private int executionStrategy(CommandLine.ParseResult parseResult) {
        try {
            initStore();
        } catch (NotAStoreException | SQLException e) {
            return -1;
        }
        return new CommandLine.RunLast().execute(parseResult);
    }

    private void initStore() throws NotAStoreException, SQLException {
        if (baseDirectory == null) {
            baseDirectory = BaseDirectoryProvider.getDefaultBaseDir();
        }

        PGPCertDCli.certificateDirectory = PGPainlessCertD.fileBased(baseDirectory, new DatabaseSubkeyLookupFactory());
    }

    public static void main(String[] args) {
        PGPCertDCli cli = new PGPCertDCli();
        new CommandLine(cli)
                .setExecutionStrategy(parserResult -> cli.executionStrategy(parserResult))
                .execute(args);
    }

    public static PGPainlessCertD getCertificateDirectory() {
        return certificateDirectory;
    }
}
