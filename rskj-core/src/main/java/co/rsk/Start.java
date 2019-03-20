/*
 * This file is part of RskJ
 * Copyright (C) 2017 RSK Labs Ltd.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */
package co.rsk;

import co.rsk.cli.migration.UnitrieMigrationTool;
import org.ethereum.core.Block;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * The entrypoint for the RSK full node
 */
public class Start {
    private static Logger logger = LoggerFactory.getLogger("start");

    public static void main(String[] args) {
        RskContext ctx = new RskContext(args);
        migrateStateToUnitrieIfNeeded(ctx);

        NodeRunner runner = ctx.getNodeRunner();
        try {
            runner.run();
            Runtime.getRuntime().addShutdownHook(new Thread(runner::stop));
        } catch (Exception e) {
            logger.error("The RSK node main thread failed, closing program", e);
            runner.stop();
            System.exit(1);
        }
    }

    // this feature is only needed until the secondFork (TBD) network upgrade is activated.
    // the whole method should be deleted after that.
    private static void migrateStateToUnitrieIfNeeded(RskContext ctx) {
        String databaseDir = ctx.getRskSystemProperties().databaseDir();
        // we need to check these before the data sources are init'ed
        boolean hasUnitrieState = Files.exists(Paths.get(databaseDir, "unitrie"));
        boolean hasOldState = Files.exists(Paths.get(databaseDir, "state"));
        if (hasUnitrieState) {
            // the node has been migrated
            return;
        }

        if (!hasOldState) {
            // node first start or after reset
            return;
        }

        // this block number has to be validated before the release to ensure the migration works fine for every user
        long minimumBlockNumberToMigrate = ctx.getRskSystemProperties().getDatabaseMigrationMinimumHeight();
        Block blockToMigrate = ctx.getBlockStore().getBestBlock();
        if (blockToMigrate == null || blockToMigrate.getNumber() < minimumBlockNumberToMigrate) {
            logger.error(
                    "The database can't be migrated because the node wasn't up to date before upgrading. " +
                    "Please reset the database or sync past block {} with the previous version to continue.",
                    minimumBlockNumberToMigrate
            );
            logger.error("Reset database or continue syncing with previous version");
            System.exit(1);
        }

        UnitrieMigrationTool unitrieMigrationTool = new UnitrieMigrationTool(
                blockToMigrate,
                databaseDir,
                ctx.getRepository(),
                ctx.getStateRootHandler(),
                ctx.getTrieConverter()
        );

        unitrieMigrationTool.migrate();
    }
}
