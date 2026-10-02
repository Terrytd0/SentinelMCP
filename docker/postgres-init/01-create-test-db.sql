-- Runs once, the first time the postgres data directory is initialised.
--
-- Creates `sentinel_test`, the database the integration suite truncates between
-- tests. A separate database rather than a set of tables in `sentinel` because
-- the integration fixtures run `TRUNCATE ... RESTART IDENTITY CASCADE` on every
-- table: pointed at a working database that is a data-loss incident, and the
-- only thing standing between a test run and someone's dev data is a string
-- in a fixture.
--
-- This only fires on a fresh volume. After the first `docker compose up`, the
-- database persists in the postgres_data volume and this script never runs
-- again -- which is why `make down` uses `down -v` if you want a clean slate.

CREATE DATABASE sentinel_test OWNER sentinel;
