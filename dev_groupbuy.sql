-- phpMyAdmin SQL Dump
-- version 4.8.3
-- https://www.phpmyadmin.net/
--
-- 主机： 127.0.0.1
-- 生成日期： 2018-12-18 11:10:02
-- 服务器版本： 10.1.36-MariaDB
-- PHP 版本： 7.2.11

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
SET AUTOCOMMIT = 0;
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- 数据库： `dev_groupbuy`
--

-- --------------------------------------------------------

--
-- 表的结构 `migrations`
--

CREATE TABLE `migrations` (
  `id` int(10) UNSIGNED NOT NULL,
  `migration` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `batch` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- --------------------------------------------------------

--
-- 表的结构 `oc_address`
--

CREATE TABLE `oc_address` (
  `address_id` int(11) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `address_1` varchar(128) NOT NULL,
  `address_2` varchar(128) NOT NULL,
  `address_3` varchar(128) NOT NULL,
  `country_id` int(11) NOT NULL DEFAULT '0',
  `state_id` int(11) NOT NULL,
  `suburb_id` int(11) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_address`
--

INSERT INTO `oc_address` (`address_id`, `customer_id`, `address_1`, `address_2`, `address_3`, `country_id`, `state_id`, `suburb_id`) VALUES
(1, 1, '1232', '123', '123', 1, 2, 5),
(2, 2, '123123', '123', '123123', 1, 1, 2),
(3, 3, '1', '1', '1', 1, 2, 5),
(4, 4, '38', '0', '0', 1, 2, 5),
(5, 5, '', '', '', 1, 1, 3),
(6, 1, '1232', '123', '123', 1, 2, 5),
(7, 2, '', '', '', 0, 0, 0),
(8, 3, '', '', '', 0, 0, 0),
(9, 4, '38', '0', '0', 1, 2, 5),
(10, 5, '', '', '', 0, 0, 0),
(11, 2, '', '', '', 1, 2, 6),
(12, 3, '', '', '', 1, 1, 2),
(13, 4, '38', '0', '0', 1, 2, 5),
(14, 5, '', '', '', 1, 2, 2),
(15, 6, '', '', '', 1, 2, 4),
(16, 7, '', '', '', 1, 2, 4),
(17, 8, '', '', '', 1, 2, 4),
(18, 9, '1', '0', '0', 1, 2, 7),
(19, 10, 'George St', 'George St', 'George St', 1, 2, 2),
(20, 11, '123', 'George St', 'Pitt St', 1, 2, 4),
(21, 12, '123', '123123', '123123', 1, 2, 8),
(22, 13, '', '', '', 1, 2, 4);

-- --------------------------------------------------------

--
-- 表的结构 `oc_affiliate`
--

CREATE TABLE `oc_affiliate` (
  `affiliate_id` int(11) NOT NULL,
  `firstname` varchar(32) NOT NULL,
  `lastname` varchar(32) NOT NULL,
  `email` varchar(96) NOT NULL,
  `telephone` varchar(32) NOT NULL,
  `fax` varchar(32) NOT NULL,
  `password` varchar(40) NOT NULL,
  `salt` varchar(9) NOT NULL,
  `company` varchar(40) NOT NULL,
  `website` varchar(255) NOT NULL,
  `address_1` varchar(128) NOT NULL,
  `address_2` varchar(128) NOT NULL,
  `city` varchar(128) NOT NULL,
  `postcode` varchar(10) NOT NULL,
  `country_id` int(11) NOT NULL,
  `zone_id` int(11) NOT NULL,
  `code` varchar(64) NOT NULL,
  `commission` decimal(4,2) NOT NULL DEFAULT '0.00',
  `tax` varchar(64) NOT NULL,
  `payment` varchar(6) NOT NULL,
  `cheque` varchar(100) NOT NULL,
  `paypal` varchar(64) NOT NULL,
  `bank_name` varchar(64) NOT NULL,
  `bank_branch_number` varchar(64) NOT NULL,
  `bank_swift_code` varchar(64) NOT NULL,
  `bank_account_name` varchar(64) NOT NULL,
  `bank_account_number` varchar(64) NOT NULL,
  `ip` varchar(40) NOT NULL,
  `status` tinyint(1) NOT NULL,
  `approved` tinyint(1) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_affiliate_activity`
--

CREATE TABLE `oc_affiliate_activity` (
  `activity_id` int(11) NOT NULL,
  `affiliate_id` int(11) NOT NULL,
  `key` varchar(64) NOT NULL,
  `data` text NOT NULL,
  `ip` varchar(40) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_affiliate_login`
--

CREATE TABLE `oc_affiliate_login` (
  `affiliate_login_id` int(11) NOT NULL,
  `email` varchar(96) NOT NULL,
  `ip` varchar(40) NOT NULL,
  `total` int(4) NOT NULL,
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_affiliate_transaction`
--

CREATE TABLE `oc_affiliate_transaction` (
  `affiliate_transaction_id` int(11) NOT NULL,
  `affiliate_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `description` text NOT NULL,
  `amount` decimal(15,4) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_api`
--

CREATE TABLE `oc_api` (
  `api_id` int(11) NOT NULL,
  `username` varchar(64) NOT NULL,
  `firstname` varchar(64) NOT NULL,
  `lastname` varchar(64) NOT NULL,
  `password` text NOT NULL,
  `status` tinyint(1) NOT NULL,
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_api`
--

INSERT INTO `oc_api` (`api_id`, `username`, `firstname`, `lastname`, `password`, `status`, `date_added`, `date_modified`) VALUES
(1, '1JDZ0NS8jRnrGh3iCsZ9eCD9CNKBwcjDTfmhsjKdlWhSDGkApgpDhylaQtvi5c7b', '', '', 'Iuii7wZzBTzwYhqVqLSA8dhs2Ht8cUtsU02ak2AEyIeIH0IiEtSzwAz40XFQWF214zjLk0AM80gWMC7nzJqg8Zf7MgxanrY30qny7qWLgZ5cpGKl8baFgqi26h3cRMRwLaEUrZGDb2safCubdmihc09qCaXXTkii2C3ryANxtM2Rs0rJWpE0v2wWgLNKszMM6gF7TdrZYYZAThCtmk6Cbw75Xzbze7NtY2oGLyi3bdTlQFuLQXMHfifVlVCWn7mH', 1, '2017-03-17 11:52:03', '2017-03-17 11:52:03');

-- --------------------------------------------------------

--
-- 表的结构 `oc_attribute`
--

CREATE TABLE `oc_attribute` (
  `attribute_id` int(11) NOT NULL,
  `attribute_group_id` int(11) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_attribute`
--

INSERT INTO `oc_attribute` (`attribute_id`, `attribute_group_id`, `sort_order`) VALUES
(1, 6, 1),
(2, 6, 5),
(3, 6, 3);

-- --------------------------------------------------------

--
-- 表的结构 `oc_attribute_description`
--

CREATE TABLE `oc_attribute_description` (
  `attribute_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_attribute_description`
--

INSERT INTO `oc_attribute_description` (`attribute_id`, `language_id`, `name`) VALUES
(1, 1, 'Description'),
(2, 1, 'No. of Cores'),
(3, 1, 'Clockspeed');

-- --------------------------------------------------------

--
-- 表的结构 `oc_attribute_group`
--

CREATE TABLE `oc_attribute_group` (
  `attribute_group_id` int(11) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_attribute_group`
--

INSERT INTO `oc_attribute_group` (`attribute_group_id`, `sort_order`) VALUES
(3, 2),
(4, 1),
(5, 3),
(6, 4);

-- --------------------------------------------------------

--
-- 表的结构 `oc_attribute_group_description`
--

CREATE TABLE `oc_attribute_group_description` (
  `attribute_group_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_attribute_group_description`
--

INSERT INTO `oc_attribute_group_description` (`attribute_group_id`, `language_id`, `name`) VALUES
(3, 1, 'Memory'),
(4, 1, 'Technical'),
(5, 1, 'Motherboard'),
(6, 1, 'Processor');

-- --------------------------------------------------------

--
-- 表的结构 `oc_banner`
--

CREATE TABLE `oc_banner` (
  `banner_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL,
  `status` tinyint(1) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_banner`
--

INSERT INTO `oc_banner` (`banner_id`, `name`, `status`) VALUES
(6, 'HP Products', 1),
(7, 'Home Page Slideshow', 1),
(8, 'Manufacturers', 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_banner_image`
--

CREATE TABLE `oc_banner_image` (
  `banner_image_id` int(11) NOT NULL,
  `banner_id` int(11) NOT NULL,
  `link` varchar(255) NOT NULL,
  `image` varchar(255) NOT NULL,
  `sort_order` int(3) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_banner_image`
--

INSERT INTO `oc_banner_image` (`banner_image_id`, `banner_id`, `link`, `image`, `sort_order`) VALUES
(79, 7, 'index.php?route=product/product&amp;path=57&amp;product_id=49', 'catalog/demo/banners/iPhone6.jpg', 0),
(87, 6, 'index.php?route=product/manufacturer/info&amp;manufacturer_id=7', 'catalog/demo/compaq_presario.jpg', 0),
(94, 8, '', 'catalog/demo/manufacturer/nfl.png', 0),
(95, 8, '', 'catalog/demo/manufacturer/redbull.png', 0),
(96, 8, '', 'catalog/demo/manufacturer/sony.png', 0),
(91, 8, '', 'catalog/demo/manufacturer/cocacola.png', 0),
(92, 8, '', 'catalog/demo/manufacturer/burgerking.png', 0),
(93, 8, '', 'catalog/demo/manufacturer/canon.png', 0),
(88, 8, '', 'catalog/demo/manufacturer/harley.png', 0),
(89, 8, '', 'catalog/demo/manufacturer/dell.png', 0),
(90, 8, '', 'catalog/demo/manufacturer/disney.png', 0),
(80, 7, '', 'catalog/demo/banners/MacBookAir.jpg', 0),
(97, 8, '', 'catalog/demo/manufacturer/starbucks.png', 0),
(98, 8, '', 'catalog/demo/manufacturer/nintendo.png', 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_banner_image_description`
--

CREATE TABLE `oc_banner_image_description` (
  `banner_image_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `banner_id` int(11) NOT NULL,
  `title` varchar(64) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_banner_image_description`
--

INSERT INTO `oc_banner_image_description` (`banner_image_id`, `language_id`, `banner_id`, `title`) VALUES
(79, 1, 7, 'iPhone 6'),
(87, 1, 6, 'HP Banner'),
(93, 1, 8, 'Canon'),
(92, 1, 8, 'Burger King'),
(91, 1, 8, 'Coca Cola'),
(90, 1, 8, 'Disney'),
(89, 1, 8, 'Dell'),
(80, 1, 7, 'MacBookAir'),
(88, 1, 8, 'Harley Davidson'),
(94, 1, 8, 'NFL'),
(95, 1, 8, 'RedBull'),
(96, 1, 8, 'Sony'),
(97, 1, 8, 'Starbucks'),
(98, 1, 8, 'Nintendo');

-- --------------------------------------------------------

--
-- 表的结构 `oc_category`
--

CREATE TABLE `oc_category` (
  `category_id` int(11) NOT NULL,
  `image` varchar(255) DEFAULT NULL,
  `parent_id` int(11) NOT NULL DEFAULT '0',
  `location_id` int(11) NOT NULL,
  `top` tinyint(1) NOT NULL,
  `column` int(3) NOT NULL,
  `sort_order` int(3) NOT NULL DEFAULT '0',
  `status` tinyint(1) NOT NULL,
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_category`
--

INSERT INTO `oc_category` (`category_id`, `image`, `parent_id`, `location_id`, `top`, `column`, `sort_order`, `status`, `date_added`, `date_modified`) VALUES
(1, NULL, 0, 4, 0, 1, 0, 1, '2017-08-01 17:16:47', '2017-08-01 17:16:47'),
(2, NULL, 0, 4, 0, 1, 1, 1, '2017-08-01 17:16:48', '2017-08-01 17:16:48'),
(3, NULL, 0, 4, 0, 1, 2, 1, '2017-08-01 17:16:50', '2017-08-01 17:16:50'),
(4, NULL, 0, 4, 0, 1, 3, 1, '2017-08-01 17:16:51', '2017-08-01 17:16:51'),
(5, NULL, 0, 4, 0, 1, 4, 1, '2017-08-01 17:16:53', '2017-08-01 17:16:53'),
(6, NULL, 0, 4, 0, 1, 5, 1, '2017-08-01 17:16:55', '2017-08-01 17:16:55'),
(7, NULL, 0, 4, 0, 1, 6, 1, '2017-08-01 17:16:58', '2017-08-01 17:16:58'),
(8, NULL, 0, 4, 0, 1, 7, 1, '2017-08-01 17:17:00', '2017-08-01 17:17:00'),
(9, NULL, 0, 4, 0, 1, 8, 1, '2017-08-01 17:17:02', '2017-08-01 17:17:02'),
(10, NULL, 0, 4, 0, 1, 9, 1, '2017-08-01 17:17:04', '2017-08-01 17:17:04'),
(11, NULL, 0, 4, 0, 1, 10, 1, '2017-08-01 17:17:07', '2017-08-01 17:17:07'),
(12, NULL, 0, -99, 0, 1, 11, 1, '2017-08-01 17:17:08', '2017-08-01 17:17:08'),
(13, NULL, 0, -99, 0, 1, 12, 1, '2017-10-04 16:53:48', '2017-10-04 16:53:48');

-- --------------------------------------------------------

--
-- 表的结构 `oc_category_description`
--

CREATE TABLE `oc_category_description` (
  `category_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `meta_title` varchar(255) NOT NULL,
  `meta_description` varchar(255) NOT NULL,
  `meta_keyword` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_category_description`
--

INSERT INTO `oc_category_description` (`category_id`, `language_id`, `name`, `description`, `meta_title`, `meta_description`, `meta_keyword`) VALUES
(1, 2, '汤面', ' ', 'soup noodle', ' ', ' '),
(2, 2, '米粉', ' ', 'potato noodle', ' ', ' '),
(3, 2, '套餐', ' ', 'meal', ' ', ' '),
(4, 2, '饮料', ' ', 'drinks', ' ', ' ');

-- --------------------------------------------------------

--
-- 表的结构 `oc_category_filter`
--

CREATE TABLE `oc_category_filter` (
  `category_id` int(11) NOT NULL,
  `filter_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_category_path`
--

CREATE TABLE `oc_category_path` (
  `category_id` int(11) NOT NULL,
  `path_id` int(11) NOT NULL,
  `level` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_category_path`
--

INSERT INTO `oc_category_path` (`category_id`, `path_id`, `level`) VALUES
(1, 1, 0),
(2, 2, 0),
(3, 3, 0),
(4, 4, 0),
(5, 5, 0),
(6, 6, 0),
(7, 7, 0),
(8, 8, 0),
(9, 9, 0),
(10, 10, 0),
(11, 11, 0),
(12, 12, 0),
(13, 13, 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_category_to_layout`
--

CREATE TABLE `oc_category_to_layout` (
  `category_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL,
  `layout_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_category_to_layout`
--

INSERT INTO `oc_category_to_layout` (`category_id`, `store_id`, `layout_id`) VALUES
(1, 0, 0),
(2, 0, 0),
(3, 0, 0),
(4, 0, 0),
(5, 0, 0),
(6, 0, 0),
(7, 0, 0),
(8, 0, 0),
(9, 0, 0),
(10, 0, 0),
(11, 0, 0),
(12, 0, 0),
(13, 0, 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_category_to_store`
--

CREATE TABLE `oc_category_to_store` (
  `category_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_category_to_store`
--

INSERT INTO `oc_category_to_store` (`category_id`, `store_id`) VALUES
(1, 0),
(2, 0),
(3, 0),
(4, 0),
(5, 0),
(6, 0),
(7, 0),
(8, 0),
(9, 0),
(10, 0),
(11, 0),
(12, 0),
(13, 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_country`
--

CREATE TABLE `oc_country` (
  `country_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL,
  `iso_code_2` varchar(2) NOT NULL,
  `iso_code_3` varchar(3) NOT NULL,
  `address_format` text NOT NULL,
  `postcode_required` tinyint(1) NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT '1'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_country`
--

INSERT INTO `oc_country` (`country_id`, `name`, `iso_code_2`, `iso_code_3`, `address_format`, `postcode_required`, `status`) VALUES
(1, 'Australia', '', '', '', 0, 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_coupon`
--

CREATE TABLE `oc_coupon` (
  `coupon_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL,
  `code` varchar(10) NOT NULL,
  `type` char(1) NOT NULL,
  `discount` decimal(15,4) NOT NULL,
  `logged` tinyint(1) NOT NULL,
  `shipping` tinyint(1) NOT NULL,
  `total` decimal(15,4) NOT NULL,
  `date_start` date NOT NULL DEFAULT '0000-00-00',
  `date_end` date NOT NULL DEFAULT '0000-00-00',
  `uses_total` int(11) NOT NULL,
  `uses_customer` varchar(11) NOT NULL,
  `status` tinyint(1) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_coupon`
--

INSERT INTO `oc_coupon` (`coupon_id`, `name`, `code`, `type`, `discount`, `logged`, `shipping`, `total`, `date_start`, `date_end`, `uses_total`, `uses_customer`, `status`, `date_added`) VALUES
(4, '-10% Discount', '2222', 'P', '10.0000', 0, 0, '0.0000', '2014-01-01', '2020-01-01', 10, '10', 0, '2009-01-27 13:55:03'),
(5, 'Free Shipping', '3333', 'P', '0.0000', 0, 1, '100.0000', '2014-01-01', '2014-02-01', 10, '10', 0, '2009-03-14 21:13:53'),
(6, '-10.00 Discount', '1111', 'F', '10.0000', 0, 0, '10.0000', '2014-01-01', '2020-01-01', 100000, '10000', 0, '2009-03-14 21:15:18');

-- --------------------------------------------------------

--
-- 表的结构 `oc_coupon_category`
--

CREATE TABLE `oc_coupon_category` (
  `coupon_id` int(11) NOT NULL,
  `category_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_coupon_history`
--

CREATE TABLE `oc_coupon_history` (
  `coupon_history_id` int(11) NOT NULL,
  `coupon_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `amount` decimal(15,4) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_coupon_product`
--

CREATE TABLE `oc_coupon_product` (
  `coupon_product_id` int(11) NOT NULL,
  `coupon_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_currency`
--

CREATE TABLE `oc_currency` (
  `currency_id` int(11) NOT NULL,
  `title` varchar(32) NOT NULL,
  `code` varchar(3) NOT NULL,
  `symbol_left` varchar(12) NOT NULL,
  `symbol_right` varchar(12) NOT NULL,
  `decimal_place` char(1) NOT NULL,
  `value` float(15,8) NOT NULL,
  `status` tinyint(1) NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_currency`
--

INSERT INTO `oc_currency` (`currency_id`, `title`, `code`, `symbol_left`, `symbol_right`, `decimal_place`, `value`, `status`, `date_modified`) VALUES
(4, 'AU Dollar', 'AUD', '$', '', '2', 1.00000000, 1, '2018-07-31 03:05:18');

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer`
--

CREATE TABLE `oc_customer` (
  `customer_id` int(11) NOT NULL,
  `customer_group_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL DEFAULT '0',
  `firstname` varchar(32) NOT NULL,
  `lastname` varchar(32) NOT NULL,
  `alias` varchar(32) NOT NULL,
  `email` varchar(96) NOT NULL,
  `telephone` varchar(32) NOT NULL,
  `fax` varchar(32) NOT NULL,
  `password` varchar(40) NOT NULL,
  `salt` varchar(9) NOT NULL,
  `upload_id` int(11) NOT NULL,
  `newsletter` tinyint(1) NOT NULL DEFAULT '0',
  `address_id` int(11) NOT NULL DEFAULT '0',
  `custom_field` text NOT NULL,
  `ip` varchar(40) NOT NULL,
  `status` tinyint(1) NOT NULL,
  `approved` tinyint(1) NOT NULL,
  `safe` tinyint(1) NOT NULL,
  `token` varchar(255) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_customer`
--

INSERT INTO `oc_customer` (`customer_id`, `customer_group_id`, `store_id`, `firstname`, `lastname`, `alias`, `email`, `telephone`, `fax`, `password`, `salt`, `upload_id`, `newsletter`, `address_id`, `custom_field`, `ip`, `status`, `approved`, `safe`, `token`, `date_added`) VALUES
(1, 1, 0, '', '', '', '123@qq.com', '', '', 'a0d6daab2d9a12be77615dca9945b77e8ec51f79', '037fc7394', 0, 0, 0, '', '182.111.155.151', 1, 1, 1, '', '2017-05-11 11:28:09'),
(2, 1, 0, '', '', '', 'admin@qq.com', '', '', 'b7d74ff457f74b8c3ba36be6c957539c4f0ceae1', '12900f2cd', 0, 0, 11, '', '115.151.184.54', 1, 1, 1, '', '2017-05-20 10:24:13'),
(3, 1, 0, '', '', '', '1232@qq.com', '', '', 'b74bf2b71eb0770275626bb339c46dd5479460df', '34703150f', 0, 0, 12, '', '103.253.25.137', 1, 1, 1, '', '2017-05-20 10:46:11'),
(4, 1, 0, 'John', 'Smith', 'Johnrating', 'grantedwins5@hotmail.com', '(02) 8090 1234', '0452 123 456', 'ee3d06811d55e869b87a9bb493af4952cf668349', 'e9517ecb4', 0, 0, 13, '', '120.26.192.76', 1, 1, 1, '', '2017-05-25 10:50:26'),
(5, 1, 0, '', '', '', '1234@qq.com', '', '', '2b3fff460afcc8241b5e5ef25855c8e71ef29b26', 'fb34c454b', 0, 0, 14, '', '127.0.0.1', 1, 1, 1, '', '2017-06-14 10:05:44'),
(6, 1, 0, '', '', '', 'qq@hotmail.com', '', '', '34ec9da24b548ea5609beffe4721ce6306ed3d03', 'b81959c10', 0, 0, 15, '', '101.187.98.39', 1, 1, 1, '', '2017-06-14 10:17:49'),
(7, 1, 0, '', '', '', '12345@qq.com', '', '', 'c5f0a2f0761dbbd356471556506f330a53f138e5', '8e4529ea2', 0, 0, 16, '', '182.111.155.151', 1, 1, 1, '', '2017-06-16 08:53:29'),
(8, 1, 0, '', '', '', 'mkl@hotmail.com', '', '', '8aa85a799766cc75958770706c64a26c1deb094a', 'fab2212e5', 0, 0, 17, '', '101.187.98.39', 1, 1, 1, '', '2017-06-16 11:50:59'),
(9, 1, 0, 'asdfqwer', 'asdfqwer', 'asdfqwer', 'asdfqwer@hotmail.com', '(02) 8090 1234', '0452 123 123', 'd3431302e1ef67d46f13883b31af58f25c7e2c2a', '63f1eaba0', 0, 0, 18, '', '101.187.98.39', 1, 1, 1, '', '2017-07-20 09:54:55'),
(10, 1, 0, '', '', '', '1122@qq.com', '', '', '45aac951f061656c2f6e45b054dc136d9ea86059', 'b0394aef3', 0, 0, 19, '', '115.151.186.216', 1, 1, 1, '', '2017-07-20 10:02:42'),
(11, 1, 0, 'aaaa', 'aaaa', 'aaaa', 'aaaa@hotmail.com', '(02) 1234 1234', '1234 123 123', 'fe2684ef66f0b59cf4ffbb88b60318e3fdc3f3ee', '306b50412', 0, 0, 20, '', '101.187.98.39', 1, 1, 1, '', '2017-07-20 10:03:59'),
(12, 1, 0, '', '', '', 'sirius@qq.com', '', '', '7676399515195083cf26a85108f026311429b22a', '7f5282878', 0, 0, 21, '', '127.0.0.1', 1, 1, 1, '', '2017-07-28 09:08:21'),
(13, 1, 0, '', '', '', 'harry@gmail.com', '', '', '48d7ac7e59de81742d0daf22949fa0d847a737b1', '100024b07', 0, 0, 22, '', '192.168.1.220', 1, 1, 1, '', '2017-08-01 17:23:09');

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_activity`
--

CREATE TABLE `oc_customer_activity` (
  `activity_id` int(11) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `key` varchar(64) NOT NULL,
  `data` text NOT NULL,
  `ip` varchar(40) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_customer_activity`
--

INSERT INTO `oc_customer_activity` (`activity_id`, `customer_id`, `key`, `data`, `ip`, `date_added`) VALUES
(1, 1, 'register', 'a:2:{s:11:\"customer_id\";i:1;s:5:\"email\";s:10:\"123@qq.com\";}', '127.0.0.1', '2017-05-11 11:28:09'),
(2, 1, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:1;}', '127.0.0.1', '2017-05-11 11:29:58'),
(3, 0, 'order_guest', 'a:2:{s:4:\"name\";s:7:\"132 123\";s:8:\"order_id\";i:3;}', '127.0.0.1', '2017-05-12 16:22:58'),
(4, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '127.0.0.1', '2017-05-18 15:45:40'),
(5, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '127.0.0.1', '2017-05-18 15:48:41'),
(6, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '127.0.0.1', '2017-05-18 15:53:31'),
(7, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '127.0.0.1', '2017-05-19 15:10:34'),
(8, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '127.0.0.1', '2017-05-19 15:16:52'),
(9, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '127.0.0.1', '2017-05-19 15:44:09'),
(10, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '115.151.184.54', '2017-05-20 10:20:51'),
(11, 2, 'register', 'a:2:{s:11:\"customer_id\";i:2;s:5:\"email\";s:12:\"admin@qq.com\";}', '115.151.184.54', '2017-05-20 10:24:13'),
(12, 3, 'register', 'a:2:{s:11:\"customer_id\";i:3;s:5:\"email\";s:11:\"1232@qq.com\";}', '103.253.25.137', '2017-05-20 10:46:11'),
(13, 0, 'order_guest', 'a:2:{s:4:\"name\";s:6:\"111 11\";s:8:\"order_id\";i:1;}', '101.187.98.39', '2017-05-22 10:07:36'),
(14, 0, 'order_guest', 'a:2:{s:4:\"name\";s:6:\"1111 1\";s:8:\"order_id\";i:2;}', '101.187.98.39', '2017-05-22 10:08:58'),
(15, 4, 'register', 'a:2:{s:11:\"customer_id\";i:4;s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-05-25 10:50:26'),
(16, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '117.44.132.159', '2017-05-25 13:24:37'),
(17, 0, 'order_guest', 'a:2:{s:4:\"name\";s:4:\"11 1\";s:8:\"order_id\";i:16;}', '101.187.98.39', '2017-05-26 07:47:13'),
(18, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:17;}', '101.187.98.39', '2017-05-26 07:48:27'),
(19, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-05-26 08:01:17'),
(20, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:18;}', '101.187.98.39', '2017-05-26 08:04:18'),
(21, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-05-26 08:51:22'),
(22, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:19;}', '101.187.98.39', '2017-05-26 08:52:16'),
(23, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:20;}', '101.187.98.39', '2017-05-26 10:54:04'),
(24, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-05-26 10:57:41'),
(25, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:21;}', '101.187.98.39', '2017-05-26 10:58:14'),
(26, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-05-26 12:25:48'),
(27, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-05-26 12:26:41'),
(28, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:22;}', '101.187.98.39', '2017-05-31 09:07:23'),
(29, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-02 08:00:14'),
(30, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-02 08:21:30'),
(31, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"3123 12312@\";s:8:\"order_id\";i:28;}', '182.103.241.63', '2017-06-02 11:53:31'),
(32, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '182.103.241.63', '2017-06-03 17:57:10'),
(33, 1, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:29;}', '182.103.241.63', '2017-06-03 17:57:17'),
(34, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:30;}', '101.187.98.39', '2017-06-05 11:33:17'),
(35, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-05 11:33:46'),
(36, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:31;}', '101.187.98.39', '2017-06-05 11:37:11'),
(37, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:32;}', '101.187.98.39', '2017-06-05 12:19:55'),
(38, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:34;}', '101.187.98.39', '2017-06-05 12:21:00'),
(39, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:35;}', '101.187.98.39', '2017-06-05 12:24:59'),
(40, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:36;}', '101.187.98.39', '2017-06-05 14:09:56'),
(41, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:38;}', '101.187.98.39', '2017-06-06 08:28:07'),
(42, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '182.111.154.134', '2017-06-06 08:39:00'),
(43, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"RICHIE WANG\";s:8:\"order_id\";i:39;}', '101.187.98.39', '2017-06-06 09:56:41'),
(44, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-06 15:46:10'),
(45, 0, 'order_guest', 'a:2:{s:4:\"name\";s:7:\"213 123\";s:8:\"order_id\";i:40;}', '182.111.154.134', '2017-06-06 15:48:22'),
(46, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"123213 213\";s:8:\"order_id\";i:41;}', '182.111.154.134', '2017-06-06 15:53:08'),
(47, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '182.111.154.134', '2017-06-06 15:53:17'),
(48, 1, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:42;}', '182.111.154.134', '2017-06-06 15:53:30'),
(49, 0, 'order_guest', 'a:2:{s:4:\"name\";s:4:\"1 11\";s:8:\"order_id\";i:43;}', '101.187.98.39', '2017-06-07 08:57:26'),
(50, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-07 09:52:58'),
(51, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:45;}', '101.187.98.39', '2017-06-07 09:53:30'),
(52, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:46;}', '101.187.98.39', '2017-06-07 09:53:56'),
(53, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:47;}', '101.187.98.39', '2017-06-07 10:13:21'),
(54, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"RICHIE WANG\";s:8:\"order_id\";i:48;}', '101.187.98.39', '2017-06-07 11:11:49'),
(55, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-07 11:24:29'),
(56, 0, 'order_guest', 'a:2:{s:4:\"name\";s:4:\"1 11\";s:8:\"order_id\";i:50;}', '101.187.98.39', '2017-06-07 11:26:23'),
(57, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:51;}', '101.187.98.39', '2017-06-07 14:11:55'),
(58, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '117.44.133.166', '2017-06-07 16:40:34'),
(59, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-13 14:02:45'),
(60, 0, 'order_guest', 'a:2:{s:4:\"name\";s:7:\"123 123\";s:8:\"order_id\";i:52;}', '182.103.241.202', '2017-06-13 14:05:21'),
(61, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:53;}', '101.187.98.39', '2017-06-13 14:06:23'),
(62, 0, 'order_guest', 'a:2:{s:4:\"name\";s:7:\"123 123\";s:8:\"order_id\";i:54;}', '182.103.241.202', '2017-06-13 14:07:38'),
(63, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '182.103.241.202', '2017-06-13 14:09:05'),
(64, 1, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:55;}', '182.103.241.202', '2017-06-13 14:09:41'),
(65, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:56;}', '101.187.98.39', '2017-06-13 14:13:02'),
(66, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:57;}', '101.187.98.39', '2017-06-13 14:20:46'),
(67, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"123123 1231\";s:8:\"order_id\";i:58;}', '117.44.133.8', '2017-06-13 16:51:44'),
(68, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"123123 1231\";s:8:\"order_id\";i:59;}', '117.44.133.8', '2017-06-13 16:51:57'),
(69, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"123123 1231\";s:8:\"order_id\";i:60;}', '117.44.133.8', '2017-06-13 16:55:13'),
(70, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '117.44.133.8', '2017-06-13 16:56:21'),
(71, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-14 09:15:31'),
(72, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:61;}', '101.187.98.39', '2017-06-14 09:15:43'),
(73, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '117.44.133.8', '2017-06-14 09:58:23'),
(74, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-14 10:05:37'),
(75, 5, 'register', 'a:2:{s:11:\"customer_id\";i:5;s:5:\"email\";s:11:\"1234@qq.com\";}', '117.44.133.8', '2017-06-14 10:05:44'),
(76, 5, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:11:\"1234@qq.com\";}', '117.44.133.8', '2017-06-14 10:07:03'),
(77, 5, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:62;}', '117.44.133.8', '2017-06-14 10:07:15'),
(78, 5, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:63;}', '117.44.133.8', '2017-06-14 10:08:59'),
(79, 6, 'register', 'a:2:{s:11:\"customer_id\";i:6;s:5:\"email\";s:14:\"qq@hotmail.com\";}', '101.187.98.39', '2017-06-14 10:17:49'),
(80, 6, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"6\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:64;}', '101.187.98.39', '2017-06-14 10:18:20'),
(81, 6, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"6\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:66;}', '101.187.98.39', '2017-06-15 07:47:50'),
(82, 6, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"6\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:67;}', '101.187.98.39', '2017-06-15 07:49:02'),
(83, 6, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"6\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:69;}', '101.187.98.39', '2017-06-15 07:49:39'),
(84, 6, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"6\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:70;}', '101.187.98.39', '2017-06-15 07:50:01'),
(85, 6, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"6\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:71;}', '101.187.98.39', '2017-06-15 07:50:27'),
(86, 6, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"6\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:72;}', '101.187.98.39', '2017-06-15 08:10:41'),
(87, 6, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"6\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:73;}', '101.187.98.39', '2017-06-15 08:15:39'),
(88, 5, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:11:\"1234@qq.com\";}', '117.44.133.8', '2017-06-15 08:40:34'),
(89, 5, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:74;}', '117.44.133.8', '2017-06-15 08:56:40'),
(90, 5, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:75;}', '117.44.133.8', '2017-06-15 08:56:54'),
(91, 5, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:76;}', '117.44.133.8', '2017-06-15 08:57:08'),
(92, 5, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:77;}', '117.44.133.8', '2017-06-15 08:57:14'),
(93, 5, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:78;}', '117.44.133.8', '2017-06-15 08:57:32'),
(94, 5, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:79;}', '117.44.133.8', '2017-06-15 08:57:45'),
(95, 5, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:80;}', '117.44.133.8', '2017-06-15 09:00:13'),
(96, 5, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:11:\"1234@qq.com\";}', '117.44.133.8', '2017-06-15 15:58:09'),
(97, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-16 08:35:25'),
(98, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:82;}', '101.187.98.39', '2017-06-16 08:36:04'),
(99, 7, 'register', 'a:2:{s:11:\"customer_id\";i:7;s:5:\"email\";s:12:\"12345@qq.com\";}', '182.111.155.151', '2017-06-16 08:53:29'),
(100, 0, 'order_guest', 'a:2:{s:4:\"name\";s:12:\"12321 123213\";s:8:\"order_id\";i:83;}', '182.111.155.151', '2017-06-16 08:55:06'),
(101, 7, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:12:\"12345@qq.com\";}', '182.111.155.151', '2017-06-16 08:55:17'),
(102, 7, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:84;}', '182.111.155.151', '2017-06-16 08:55:27'),
(103, 7, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:85;}', '182.111.155.151', '2017-06-16 08:56:48'),
(104, 7, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:86;}', '182.111.155.151', '2017-06-16 08:57:29'),
(105, 7, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:87;}', '182.111.155.151', '2017-06-16 08:57:39'),
(106, 7, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:88;}', '182.111.155.151', '2017-06-16 08:57:48'),
(107, 7, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:89;}', '182.111.155.151', '2017-06-16 08:57:57'),
(108, 7, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:90;}', '182.111.155.151', '2017-06-16 08:58:03'),
(109, 7, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:91;}', '182.111.155.151', '2017-06-16 08:58:13'),
(110, 7, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"7\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:92;}', '182.111.155.151', '2017-06-16 08:58:30'),
(111, 8, 'register', 'a:2:{s:11:\"customer_id\";i:8;s:5:\"email\";s:15:\"mkl@hotmail.com\";}', '101.187.98.39', '2017-06-16 11:50:59'),
(112, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:93;}', '101.187.98.39', '2017-06-16 11:51:34'),
(113, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:94;}', '101.187.98.39', '2017-06-16 11:53:31'),
(114, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:95;}', '101.187.98.39', '2017-06-16 11:53:55'),
(115, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:96;}', '101.187.98.39', '2017-06-16 11:54:13'),
(116, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:97;}', '101.187.98.39', '2017-06-16 11:54:30'),
(117, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:99;}', '101.187.98.39', '2017-06-16 11:54:57'),
(118, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:100;}', '101.187.98.39', '2017-06-16 11:55:23'),
(119, 1, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:10:\"123@qq.com\";}', '182.111.155.151', '2017-06-16 11:55:37'),
(120, 8, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:15:\"mkl@hotmail.com\";}', '101.187.98.39', '2017-06-16 11:56:43'),
(121, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:101;}', '101.187.98.39', '2017-06-16 11:59:34'),
(122, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:102;}', '101.187.98.39', '2017-06-16 11:59:57'),
(123, 1, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:103;}', '182.111.155.151', '2017-06-16 12:02:32'),
(124, 1, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:104;}', '182.111.155.151', '2017-06-16 12:02:45'),
(125, 1, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:105;}', '182.111.155.151', '2017-06-16 12:02:56'),
(126, 1, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:106;}', '182.111.155.151', '2017-06-16 12:03:06'),
(127, 1, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"1\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:107;}', '182.111.155.151', '2017-06-16 12:03:13'),
(128, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:108;}', '101.187.98.39', '2017-06-16 12:06:18'),
(129, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:109;}', '101.187.98.39', '2017-06-16 12:06:54'),
(130, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:110;}', '101.187.98.39', '2017-06-16 12:07:09'),
(131, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:111;}', '101.187.98.39', '2017-06-16 12:07:32'),
(132, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:112;}', '101.187.98.39', '2017-06-16 12:07:50'),
(133, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:113;}', '101.187.98.39', '2017-06-16 12:08:04'),
(134, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:114;}', '101.187.98.39', '2017-06-16 12:08:25'),
(135, 8, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"8\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:115;}', '101.187.98.39', '2017-06-16 12:11:59'),
(136, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-16 12:33:49'),
(137, 0, 'order_guest', 'a:2:{s:4:\"name\";s:14:\"1231231 123123\";s:8:\"order_id\";i:127;}', '182.111.155.151', '2017-06-16 13:57:33'),
(138, 0, 'order_guest', 'a:2:{s:4:\"name\";s:14:\"1231231 123123\";s:8:\"order_id\";i:136;}', '182.111.155.151', '2017-06-16 14:18:20'),
(139, 0, 'order_guest', 'a:2:{s:4:\"name\";s:14:\"1231231 123123\";s:8:\"order_id\";i:142;}', '182.111.155.151', '2017-06-16 14:19:50'),
(140, 0, 'order_guest', 'a:2:{s:4:\"name\";s:14:\"1231231 123123\";s:8:\"order_id\";i:148;}', '182.111.155.151', '2017-06-16 14:34:31'),
(141, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:153;}', '101.187.98.39', '2017-06-16 15:20:44'),
(142, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-21 15:13:58'),
(143, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-22 08:15:23'),
(144, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-23 08:34:14'),
(145, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-23 09:30:08'),
(146, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-23 09:33:57'),
(147, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-06-23 10:24:27'),
(148, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:165;}', '101.187.98.39', '2017-06-27 09:02:28'),
(149, 0, 'order_guest', 'a:2:{s:4:\"name\";s:12:\"firsts lasts\";s:8:\"order_id\";i:169;}', '115.151.186.5', '2017-06-30 16:38:47'),
(150, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-03 08:19:53'),
(151, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:171;}', '101.187.98.39', '2017-07-03 08:31:43'),
(152, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:173;}', '101.187.98.39', '2017-07-03 10:43:49'),
(153, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-03 11:30:28'),
(154, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"Harry Chen\";s:8:\"order_id\";i:174;}', '101.187.98.39', '2017-07-03 11:59:06'),
(155, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-03 12:54:18'),
(156, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:177;}', '101.187.98.39', '2017-07-03 12:57:00'),
(157, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-03 14:55:10'),
(158, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:180;}', '101.187.98.39', '2017-07-04 09:37:25'),
(159, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:181;}', '101.187.98.39', '2017-07-04 10:27:11'),
(160, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:1;}', '101.187.98.39', '2017-07-11 08:27:11'),
(161, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:15;}', '101.187.98.39', '2017-07-11 12:41:15'),
(162, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-11 13:42:01'),
(163, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-11 13:43:02'),
(164, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-11 13:43:36'),
(165, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:18;}', '101.187.98.39', '2017-07-11 13:53:40'),
(166, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:19;}', '101.187.98.39', '2017-07-11 14:43:50'),
(167, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-11 15:01:31'),
(168, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-11 15:01:53'),
(169, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-11 15:05:17'),
(170, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:20;}', '101.187.98.39', '2017-07-11 15:07:38'),
(171, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:21;}', '101.187.98.39', '2017-07-11 15:23:48'),
(172, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-11 15:26:51'),
(173, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:22;}', '101.187.98.39', '2017-07-11 15:28:33'),
(174, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-12 08:34:36'),
(175, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:23;}', '101.187.98.39', '2017-07-12 08:36:12'),
(176, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:24;}', '101.187.98.39', '2017-07-12 08:38:39'),
(177, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:26;}', '101.187.98.39', '2017-07-12 08:41:05'),
(178, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:27;}', '101.187.98.39', '2017-07-12 08:43:48'),
(179, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-12 08:57:05'),
(180, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:28;}', '101.187.98.39', '2017-07-12 08:59:11'),
(181, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:29;}', '101.187.98.39', '2017-07-12 09:28:16'),
(182, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:32;}', '115.151.186.197', '2017-07-17 10:20:23'),
(183, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:33;}', '115.151.186.197', '2017-07-17 10:22:00'),
(184, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:34;}', '115.151.186.197', '2017-07-17 10:29:15'),
(185, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:35;}', '115.151.186.197', '2017-07-17 10:38:11'),
(186, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:36;}', '101.187.98.39', '2017-07-18 08:11:10'),
(187, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:38;}', '101.187.98.39', '2017-07-18 08:14:32'),
(188, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-18 08:24:07'),
(189, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:39;}', '101.187.98.39', '2017-07-18 08:26:21'),
(190, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-18 08:36:39'),
(191, 0, 'order_guest', 'a:2:{s:4:\"name\";s:9:\"fist last\";s:8:\"order_id\";i:40;}', '115.151.186.216', '2017-07-19 19:17:05'),
(192, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-20 08:10:18'),
(193, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:41;}', '101.187.98.39', '2017-07-20 08:10:23'),
(194, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:44;}', '101.187.98.39', '2017-07-20 08:29:54'),
(195, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-20 08:30:29'),
(196, 4, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:5:\"email\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-20 08:31:24'),
(197, 4, 'order_account', 'a:3:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:10:\"John Smith\";s:8:\"order_id\";i:45;}', '101.187.98.39', '2017-07-20 08:42:08'),
(198, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-20 09:54:08'),
(199, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-20 09:54:22'),
(200, 9, 'register', 'a:2:{s:11:\"customer_id\";i:9;s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-20 09:54:55'),
(201, 9, 'detail', 'a:2:{s:11:\"customer_id\";s:1:\"9\";s:5:\"email\";s:20:\"asdfqwer@hotmail.com\";}', '101.187.98.39', '2017-07-20 09:55:32'),
(202, 10, 'register', 'a:2:{s:11:\"customer_id\";i:10;s:5:\"email\";s:11:\"1122@qq.com\";}', '115.151.186.216', '2017-07-20 10:02:42'),
(203, 10, 'detail', 'a:2:{s:11:\"customer_id\";s:2:\"10\";s:5:\"email\";s:11:\"1122@qq.com\";}', '115.151.186.216', '2017-07-20 10:02:50'),
(204, 11, 'register', 'a:2:{s:11:\"customer_id\";i:11;s:5:\"email\";s:16:\"aaaa@hotmail.com\";}', '101.187.98.39', '2017-07-20 10:03:59'),
(205, 11, 'detail', 'a:2:{s:11:\"customer_id\";s:2:\"11\";s:5:\"email\";s:16:\"aaaa@hotmail.com\";}', '101.187.98.39', '2017-07-20 10:04:40'),
(206, 11, 'detail', 'a:2:{s:11:\"customer_id\";s:2:\"11\";s:5:\"email\";s:16:\"aaaa@hotmail.com\";}', '101.187.98.39', '2017-07-20 10:04:45'),
(207, 10, 'detail', 'a:2:{s:11:\"customer_id\";s:2:\"10\";s:5:\"email\";s:11:\"1122@qq.com\";}', '115.151.186.216', '2017-07-20 10:06:30'),
(208, 10, 'detail', 'a:2:{s:11:\"customer_id\";s:2:\"10\";s:5:\"email\";s:11:\"1122@qq.com\";}', '115.151.186.216', '2017-07-20 10:08:13'),
(209, 11, 'detail', 'a:2:{s:11:\"customer_id\";s:2:\"11\";s:5:\"email\";s:16:\"aaaa@hotmail.com\";}', '101.187.98.39', '2017-07-20 10:08:41'),
(210, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:47;}', '101.187.98.39', '2017-07-21 09:45:28'),
(211, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:48;}', '101.187.98.39', '2017-07-21 09:46:25'),
(212, 4, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"4\";s:4:\"name\";s:24:\"grantedwins5@hotmail.com\";}', '101.187.98.39', '2017-07-21 09:56:36'),
(213, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"1 1\";s:8:\"order_id\";i:54;}', '101.187.98.39', '2017-07-21 11:57:30'),
(214, 0, 'order_guest', 'a:2:{s:4:\"name\";s:9:\"fist last\";s:8:\"order_id\";i:58;}', '127.0.0.1', '2017-07-24 14:37:48'),
(215, 0, 'order_guest', 'a:2:{s:4:\"name\";s:9:\"fist last\";s:8:\"order_id\";i:60;}', '127.0.0.1', '2017-07-24 14:45:03'),
(216, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:61;}', '127.0.0.1', '2017-07-24 15:34:27'),
(217, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:62;}', '127.0.0.1', '2017-07-24 15:56:54'),
(218, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:65;}', '127.0.0.1', '2017-07-24 16:25:52'),
(219, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:66;}', '127.0.0.1', '2017-07-24 16:32:33'),
(220, 12, 'register', 'a:2:{s:11:\"customer_id\";i:12;s:5:\"email\";s:13:\"sirius@qq.com\";}', '127.0.0.1', '2017-07-28 09:08:21'),
(221, 12, 'detail', 'a:2:{s:11:\"customer_id\";s:2:\"12\";s:5:\"email\";s:13:\"sirius@qq.com\";}', '127.0.0.1', '2017-07-28 09:09:59'),
(222, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"first first\";s:8:\"order_id\";i:67;}', '127.0.0.1', '2017-07-28 14:44:45'),
(223, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"first first\";s:8:\"order_id\";i:68;}', '127.0.0.1', '2017-07-28 14:52:40'),
(224, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"first first\";s:8:\"order_id\";i:69;}', '127.0.0.1', '2017-07-28 14:56:53'),
(225, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"first first\";s:8:\"order_id\";i:70;}', '127.0.0.1', '2017-07-28 15:14:42'),
(226, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"first first\";s:8:\"order_id\";i:71;}', '127.0.0.1', '2017-07-28 15:39:59'),
(227, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"first first\";s:8:\"order_id\";i:72;}', '127.0.0.1', '2017-07-28 15:49:19'),
(228, 0, 'order_guest', 'a:2:{s:4:\"name\";s:11:\"first first\";s:8:\"order_id\";i:74;}', '127.0.0.1', '2017-07-28 16:00:31'),
(229, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:75;}', '127.0.0.1', '2017-07-28 16:16:55'),
(230, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:76;}', '127.0.0.1', '2017-07-28 16:24:47'),
(231, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:77;}', '127.0.0.1', '2017-07-28 17:08:36'),
(232, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:78;}', '127.0.0.1', '2017-07-28 17:12:57'),
(233, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:79;}', '127.0.0.1', '2017-07-28 17:15:59'),
(234, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:80;}', '127.0.0.1', '2017-07-28 17:17:08'),
(235, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"first last\";s:8:\"order_id\";i:81;}', '127.0.0.1', '2017-07-28 17:32:11'),
(236, 5, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:11:\"1234@qq.com\";}', '127.0.0.1', '2017-07-31 09:20:17'),
(237, 5, 'login', 'a:2:{s:11:\"customer_id\";s:1:\"5\";s:4:\"name\";s:11:\"1234@qq.com\";}', '127.0.0.1', '2017-07-31 09:25:17'),
(238, 0, 'order_guest', 'a:2:{s:4:\"name\";s:14:\"1laost fitlsar\";s:8:\"order_id\";i:85;}', '127.0.0.1', '2017-07-31 12:55:40'),
(239, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:1;}', '192.168.1.220', '2017-08-01 17:18:48'),
(240, 13, 'register', 'a:2:{s:11:\"customer_id\";i:13;s:5:\"email\";s:15:\"harry@gmail.com\";}', '192.168.1.220', '2017-08-01 17:23:09'),
(241, 13, 'order_account', 'a:3:{s:11:\"customer_id\";s:2:\"13\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:2;}', '192.168.1.220', '2017-08-01 17:23:34'),
(242, 13, 'order_account', 'a:3:{s:11:\"customer_id\";s:2:\"13\";s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:3;}', '192.168.1.220', '2017-08-01 17:35:14'),
(243, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:4;}', '192.168.1.220', '2017-08-02 11:07:52'),
(244, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:5;}', '192.168.1.220', '2017-08-02 15:26:14'),
(245, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:6;}', '192.168.1.220', '2017-08-02 15:33:00'),
(246, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:7;}', '192.168.1.220', '2017-08-02 15:39:38'),
(247, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"a badafdsa\";s:8:\"order_id\";i:8;}', '192.168.1.220', '2017-08-04 11:38:40'),
(248, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"a badafdsa\";s:8:\"order_id\";i:11;}', '192.168.1.220', '2017-08-04 12:02:48'),
(249, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"a badafdsa\";s:8:\"order_id\";i:12;}', '192.168.1.220', '2017-08-04 12:14:57'),
(250, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:13;}', '192.168.1.220', '2017-08-09 12:26:37'),
(251, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:14;}', '192.168.1.220', '2017-08-09 12:32:38'),
(252, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:15;}', '192.168.1.220', '2017-08-09 12:34:15'),
(253, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:16;}', '192.168.1.220', '2017-08-10 11:52:12'),
(254, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:17;}', '192.168.1.220', '2017-08-16 17:50:49'),
(255, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:18;}', '192.168.1.220', '2017-08-16 17:58:02'),
(256, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:19;}', '192.168.1.220', '2017-08-16 18:23:56'),
(257, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:20;}', '192.168.1.220', '2017-08-17 10:35:37'),
(258, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:21;}', '192.168.1.220', '2017-08-17 10:41:40'),
(259, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:22;}', '192.168.1.220', '2017-08-22 13:18:59'),
(260, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:23;}', '192.168.1.220', '2017-08-22 13:20:35'),
(261, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:24;}', '192.168.1.220', '2017-08-22 14:00:26'),
(262, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"s s\";s:8:\"order_id\";i:25;}', '192.168.1.220', '2017-08-25 16:50:44'),
(263, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"s s\";s:8:\"order_id\";i:26;}', '192.168.1.220', '2017-08-25 16:57:08'),
(264, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"s s\";s:8:\"order_id\";i:27;}', '192.168.1.220', '2017-08-25 16:59:16'),
(265, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"s s\";s:8:\"order_id\";i:28;}', '192.168.1.220', '2017-08-25 17:43:05'),
(266, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"s s\";s:8:\"order_id\";i:29;}', '192.168.1.220', '2017-08-25 18:01:16'),
(267, 0, 'order_guest', 'a:2:{s:4:\"name\";s:4:\"a2 b\";s:8:\"order_id\";i:30;}', '192.168.1.220', '2017-08-28 15:56:12'),
(268, 0, 'order_guest', 'a:2:{s:4:\"name\";s:4:\"a2 b\";s:8:\"order_id\";i:31;}', '192.168.1.220', '2017-08-28 16:08:49'),
(269, 0, 'order_guest', 'a:2:{s:4:\"name\";s:4:\"a2 b\";s:8:\"order_id\";i:32;}', '192.168.1.220', '2017-08-29 17:13:55'),
(270, 0, 'order_guest', 'a:2:{s:4:\"name\";s:4:\"a2 b\";s:8:\"order_id\";i:33;}', '192.168.1.220', '2017-08-29 17:49:54'),
(271, 0, 'order_guest', 'a:2:{s:4:\"name\";s:4:\"a2 b\";s:8:\"order_id\";i:34;}', '192.168.1.220', '2017-08-29 17:52:08'),
(272, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:35;}', '192.168.1.220', '2017-09-07 16:36:19'),
(273, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:36;}', '192.168.1.220', '2017-09-07 17:02:35'),
(274, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:37;}', '192.168.1.220', '2017-09-07 17:06:53'),
(275, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:38;}', '192.168.1.220', '2017-09-07 17:11:07'),
(276, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:39;}', '192.168.1.220', '2017-09-07 17:11:55'),
(277, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:40;}', '192.168.1.220', '2017-09-07 17:19:02'),
(278, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:41;}', '192.168.1.220', '2017-09-07 17:58:27'),
(279, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:42;}', '192.168.1.220', '2017-09-07 18:04:43'),
(280, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:43;}', '192.168.1.220', '2017-09-07 18:13:37'),
(281, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:44;}', '192.168.1.220', '2017-09-07 18:23:55'),
(282, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:45;}', '192.168.1.220', '2017-09-07 18:29:41'),
(283, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:46;}', '192.168.1.220', '2017-09-07 18:34:45'),
(284, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:47;}', '192.168.1.220', '2017-09-07 18:41:21'),
(285, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:48;}', '192.168.1.220', '2017-09-07 18:43:08'),
(286, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:49;}', '192.168.1.220', '2017-09-07 18:45:13'),
(287, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:50;}', '192.168.1.220', '2017-09-07 18:51:54'),
(288, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:51;}', '192.168.1.220', '2017-09-07 18:53:38'),
(289, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:52;}', '192.168.1.220', '2017-09-07 18:55:53'),
(290, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:53;}', '192.168.1.220', '2017-09-08 10:41:13'),
(291, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:54;}', '192.168.1.220', '2017-09-08 10:50:20'),
(292, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:55;}', '192.168.1.220', '2017-09-08 10:53:57'),
(293, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:56;}', '192.168.1.220', '2017-09-13 15:29:06'),
(294, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:57;}', '192.168.1.220', '2017-09-13 16:11:16'),
(295, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:58;}', '192.168.1.220', '2017-09-13 16:16:42'),
(296, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:59;}', '192.168.1.220', '2017-09-13 16:18:58'),
(297, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:60;}', '192.168.1.220', '2017-09-13 16:23:12'),
(298, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:61;}', '192.168.1.220', '2017-09-13 16:24:54'),
(299, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:62;}', '192.168.1.220', '2017-09-13 16:25:34'),
(300, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:63;}', '192.168.1.220', '2017-09-13 16:58:51'),
(301, 0, 'order_guest', 'a:2:{s:4:\"name\";s:4:\"a2 b\";s:8:\"order_id\";i:64;}', '192.168.1.220', '2017-09-14 13:55:38'),
(302, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:65;}', '192.168.1.220', '2017-09-20 11:07:17'),
(303, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:66;}', '192.168.1.220', '2017-09-20 11:15:15'),
(304, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:67;}', '192.168.1.220', '2017-09-28 14:38:15'),
(305, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:68;}', '192.168.1.220', '2017-09-29 18:41:08'),
(306, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:69;}', '192.168.1.220', '2017-09-29 18:54:59'),
(307, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:70;}', '192.168.1.220', '2017-09-29 19:00:45'),
(308, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:71;}', '192.168.1.220', '2017-09-29 19:04:54'),
(309, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:73;}', '192.168.1.220', '2017-09-29 19:11:39'),
(310, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:74;}', '192.168.1.220', '2017-09-29 19:17:28'),
(311, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:75;}', '192.168.1.220', '2017-09-29 19:20:23'),
(312, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:76;}', '192.168.1.220', '2017-09-29 19:28:43'),
(313, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:77;}', '192.168.1.220', '2017-09-29 19:32:40'),
(314, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:78;}', '192.168.1.220', '2017-09-29 19:35:49'),
(315, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:79;}', '192.168.1.220', '2017-09-29 19:51:40'),
(316, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:80;}', '192.168.1.220', '2017-09-29 19:58:04'),
(317, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:81;}', '192.168.1.220', '2017-09-29 20:00:20'),
(318, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:82;}', '192.168.1.220', '2017-09-29 20:02:22'),
(319, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:83;}', '192.168.1.220', '2017-09-29 20:06:19'),
(320, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:84;}', '192.168.1.220', '2017-09-29 20:07:35'),
(321, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:85;}', '192.168.1.220', '2017-10-03 10:01:56'),
(322, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:86;}', '192.168.1.220', '2017-10-03 10:05:34'),
(323, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:87;}', '192.168.1.220', '2017-10-03 10:08:24'),
(324, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:88;}', '192.168.1.220', '2017-10-03 10:17:50'),
(325, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:89;}', '192.168.1.220', '2017-10-03 10:19:12'),
(326, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:90;}', '192.168.1.220', '2017-10-03 10:22:53'),
(327, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:91;}', '192.168.1.220', '2017-10-03 10:31:27'),
(328, 0, 'order_guest', 'a:2:{s:4:\"name\";s:10:\"a badafdsa\";s:8:\"order_id\";i:92;}', '192.168.1.220', '2017-10-20 11:43:02'),
(329, 0, 'order_guest', 'a:2:{s:4:\"name\";s:5:\"a2 a3\";s:8:\"order_id\";i:93;}', '192.168.1.220', '2017-10-23 12:50:41'),
(330, 0, 'order_guest', 'a:2:{s:4:\"name\";s:5:\"a2 a3\";s:8:\"order_id\";i:94;}', '192.168.1.220', '2017-10-23 12:52:29'),
(331, 0, 'order_guest', 'a:2:{s:4:\"name\";s:5:\"a2 a3\";s:8:\"order_id\";i:95;}', '192.168.1.220', '2017-10-23 12:54:12'),
(332, 0, 'order_guest', 'a:2:{s:4:\"name\";s:5:\"a2 a3\";s:8:\"order_id\";i:96;}', '192.168.1.220', '2017-10-23 12:55:58'),
(333, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:97;}', '192.168.1.220', '2017-10-24 11:11:31'),
(334, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:98;}', '192.168.1.220', '2017-10-24 12:24:14'),
(335, 0, 'order_guest', 'a:2:{s:4:\"name\";s:9:\"test test\";s:8:\"order_id\";i:99;}', '192.168.1.220', '2017-11-17 12:03:57'),
(336, 0, 'order_guest', 'a:2:{s:4:\"name\";s:9:\"test test\";s:8:\"order_id\";i:101;}', '192.168.1.220', '2017-11-17 12:10:17'),
(337, 0, 'order_guest', 'a:2:{s:4:\"name\";s:9:\"test test\";s:8:\"order_id\";i:102;}', '192.168.1.220', '2017-11-17 12:12:46'),
(338, 0, 'order_guest', 'a:2:{s:4:\"name\";s:9:\"test test\";s:8:\"order_id\";i:103;}', '192.168.1.220', '2017-11-17 12:19:56'),
(339, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"s s\";s:8:\"order_id\";i:104;}', '192.168.1.220', '2017-11-17 18:39:34'),
(340, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"s s\";s:8:\"order_id\";i:105;}', '192.168.1.220', '2017-11-17 18:42:50'),
(341, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:106;}', '192.168.1.220', '2018-01-10 12:09:34'),
(342, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"f a\";s:8:\"order_id\";i:107;}', '192.168.1.220', '2018-01-12 12:38:15'),
(343, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"f a\";s:8:\"order_id\";i:108;}', '192.168.1.220', '2018-01-12 12:40:12'),
(344, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:109;}', '192.168.1.220', '2018-01-17 14:13:27'),
(345, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:110;}', '192.168.1.220', '2018-01-17 14:21:10'),
(346, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a b\";s:8:\"order_id\";i:111;}', '192.168.1.220', '2018-01-17 14:22:27'),
(347, 0, 'order_guest', 'a:2:{s:4:\"name\";s:3:\"a a\";s:8:\"order_id\";i:112;}', '192.168.1.220', '2018-01-19 15:51:33'),
(348, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:113;}', '192.168.1.220', '2018-01-19 15:58:11'),
(349, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:113;}', '192.168.1.220', '2018-01-19 15:59:18'),
(350, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:114;}', '192.168.1.220', '2018-01-19 16:00:04'),
(351, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:114;}', '192.168.1.220', '2018-01-19 16:01:27'),
(352, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:115;}', '192.168.1.220', '2018-01-19 16:02:07'),
(353, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:116;}', '192.168.1.220', '2018-01-19 16:13:28'),
(354, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:117;}', '192.168.1.220', '2018-01-19 16:19:07'),
(355, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:118;}', '192.168.1.220', '2018-01-19 16:23:46'),
(356, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:121;}', '192.168.1.220', '2018-01-19 16:30:36'),
(357, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:122;}', '192.168.1.220', '2018-01-22 12:50:22'),
(358, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:123;}', '192.168.1.220', '2018-01-22 12:51:20'),
(359, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:124;}', '192.168.1.220', '2018-01-22 12:52:41'),
(360, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:125;}', '192.168.1.220', '2018-01-22 12:58:46'),
(361, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:126;}', '192.168.1.220', '2018-01-22 13:47:34'),
(362, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:127;}', '192.168.1.220', '2018-01-22 15:12:19'),
(363, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:128;}', '192.168.1.220', '2018-01-22 15:12:42'),
(364, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:129;}', '192.168.1.220', '2018-01-22 15:13:24'),
(365, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:130;}', '192.168.1.220', '2018-01-22 15:14:45'),
(366, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:131;}', '192.168.1.220', '2018-01-22 15:18:15'),
(367, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:132;}', '192.168.1.220', '2018-01-22 15:31:31'),
(368, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:133;}', '192.168.1.246', '2018-01-24 20:04:04'),
(369, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:134;}', '192.168.1.246', '2018-01-24 20:07:00'),
(370, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:135;}', '192.168.1.209', '2018-01-25 12:22:06'),
(371, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:136;}', '192.168.1.220', '2018-01-25 13:04:25'),
(372, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:137;}', '192.168.1.220', '2018-01-25 13:23:02'),
(373, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:138;}', '192.168.1.220', '2018-01-25 13:24:38'),
(374, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:139;}', '192.168.1.220', '2018-01-25 14:22:20');
INSERT INTO `oc_customer_activity` (`activity_id`, `customer_id`, `key`, `data`, `ip`, `date_added`) VALUES
(375, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:140;}', '192.168.1.220', '2018-01-25 14:46:21'),
(376, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:141;}', '192.168.1.220', '2018-06-20 18:17:37'),
(377, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:142;}', '192.168.1.220', '2018-06-20 18:19:03'),
(378, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:143;}', '192.168.1.220', '2018-06-20 18:30:11'),
(379, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:144;}', '192.168.1.220', '2018-06-20 19:08:47'),
(380, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:145;}', '192.168.1.220', '2018-06-20 19:19:49'),
(381, 0, 'order_guest', 'a:2:{s:4:\"name\";s:1:\" \";s:8:\"order_id\";i:146;}', '192.168.1.220', '2018-06-20 19:34:55');

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_ban_ip`
--

CREATE TABLE `oc_customer_ban_ip` (
  `customer_ban_ip_id` int(11) NOT NULL,
  `ip` varchar(40) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_group`
--

CREATE TABLE `oc_customer_group` (
  `customer_group_id` int(11) NOT NULL,
  `approval` int(1) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_customer_group`
--

INSERT INTO `oc_customer_group` (`customer_group_id`, `approval`, `sort_order`) VALUES
(1, 0, 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_group_description`
--

CREATE TABLE `oc_customer_group_description` (
  `customer_group_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(32) NOT NULL,
  `description` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_customer_group_description`
--

INSERT INTO `oc_customer_group_description` (`customer_group_id`, `language_id`, `name`, `description`) VALUES
(1, 1, 'Default', 'test');

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_history`
--

CREATE TABLE `oc_customer_history` (
  `customer_history_id` int(11) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `comment` text NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_ip`
--

CREATE TABLE `oc_customer_ip` (
  `customer_ip_id` int(11) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `ip` varchar(40) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_customer_ip`
--

INSERT INTO `oc_customer_ip` (`customer_ip_id`, `customer_id`, `ip`, `date_added`) VALUES
(1, 1, '127.0.0.1', '2017-05-11 11:28:09'),
(2, 1, '115.151.184.54', '2017-05-20 10:20:51'),
(3, 2, '115.151.184.54', '2017-05-20 10:24:14'),
(4, 3, '103.253.25.137', '2017-05-20 10:46:11'),
(5, 4, '101.187.98.39', '2017-05-25 10:50:26'),
(6, 1, '117.44.132.159', '2017-05-25 13:24:37'),
(7, 1, '182.103.241.63', '2017-06-03 17:57:10'),
(8, 1, '182.111.154.134', '2017-06-06 08:39:01'),
(9, 4, '120.26.192.76', '2017-06-07 10:05:24'),
(10, 1, '117.44.133.166', '2017-06-07 16:40:34'),
(11, 1, '182.103.241.202', '2017-06-13 14:09:05'),
(12, 1, '117.44.133.8', '2017-06-13 16:56:21'),
(13, 5, '117.44.133.8', '2017-06-14 10:05:44'),
(14, 6, '101.187.98.39', '2017-06-14 10:17:50'),
(15, 7, '182.111.155.151', '2017-06-16 08:53:29'),
(16, 8, '101.187.98.39', '2017-06-16 11:51:00'),
(17, 1, '182.111.155.151', '2017-06-16 11:55:38'),
(18, 9, '101.187.98.39', '2017-07-20 09:54:55'),
(19, 10, '115.151.186.216', '2017-07-20 10:02:42'),
(20, 11, '101.187.98.39', '2017-07-20 10:04:00'),
(21, 12, '127.0.0.1', '2017-07-28 09:08:21'),
(22, 5, '127.0.0.1', '2017-07-31 09:20:17'),
(23, 13, '192.168.1.220', '2017-08-01 17:23:09');

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_login`
--

CREATE TABLE `oc_customer_login` (
  `customer_login_id` int(11) NOT NULL,
  `email` varchar(96) NOT NULL,
  `ip` varchar(40) NOT NULL,
  `total` int(4) NOT NULL,
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_customer_login`
--

INSERT INTO `oc_customer_login` (`customer_login_id`, `email`, `ip`, `total`, `date_added`, `date_modified`) VALUES
(3, 'qzwxecrv@hotmail.com', '101.187.98.39', 1, '2017-05-25 02:48:09', '2017-05-25 02:48:09'),
(4, 'wxecrvtb@hotmail.com', '101.187.98.39', 5, '2017-05-25 02:48:15', '2017-05-25 02:48:30'),
(5, 'asdf@hotmail.com', '101.187.98.39', 2, '2017-05-26 00:00:57', '2017-05-26 00:01:02'),
(6, 'test123', '182.103.241.202', 3, '2017-06-13 06:08:31', '2017-06-13 06:08:36'),
(11, 'richad521@hotmail.com', '101.187.98.39', 2, '2017-06-23 02:23:56', '2017-06-23 02:24:04'),
(10, '', '174.127.133.44', 1, '2017-06-19 21:28:28', '2017-06-19 21:28:28');

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_online`
--

CREATE TABLE `oc_customer_online` (
  `ip` varchar(40) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `url` text NOT NULL,
  `referer` text NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_reward`
--

CREATE TABLE `oc_customer_reward` (
  `customer_reward_id` int(11) NOT NULL,
  `customer_id` int(11) NOT NULL DEFAULT '0',
  `order_id` int(11) NOT NULL DEFAULT '0',
  `description` text NOT NULL,
  `points` int(8) NOT NULL DEFAULT '0',
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_customer_transaction`
--

CREATE TABLE `oc_customer_transaction` (
  `customer_transaction_id` int(11) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `description` text NOT NULL,
  `amount` decimal(15,4) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_custom_field`
--

CREATE TABLE `oc_custom_field` (
  `custom_field_id` int(11) NOT NULL,
  `type` varchar(32) NOT NULL,
  `value` text NOT NULL,
  `location` varchar(7) NOT NULL,
  `status` tinyint(1) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_custom_field_customer_group`
--

CREATE TABLE `oc_custom_field_customer_group` (
  `custom_field_id` int(11) NOT NULL,
  `customer_group_id` int(11) NOT NULL,
  `required` tinyint(1) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_custom_field_description`
--

CREATE TABLE `oc_custom_field_description` (
  `custom_field_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_custom_field_value`
--

CREATE TABLE `oc_custom_field_value` (
  `custom_field_value_id` int(11) NOT NULL,
  `custom_field_id` int(11) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_custom_field_value_description`
--

CREATE TABLE `oc_custom_field_value_description` (
  `custom_field_value_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `custom_field_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_download`
--

CREATE TABLE `oc_download` (
  `download_id` int(11) NOT NULL,
  `filename` varchar(128) NOT NULL,
  `mask` varchar(128) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_download_description`
--

CREATE TABLE `oc_download_description` (
  `download_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_event`
--

CREATE TABLE `oc_event` (
  `event_id` int(11) NOT NULL,
  `code` varchar(32) NOT NULL,
  `trigger` text NOT NULL,
  `action` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_extension`
--

CREATE TABLE `oc_extension` (
  `extension_id` int(11) NOT NULL,
  `type` varchar(32) NOT NULL,
  `code` varchar(32) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_extension`
--

INSERT INTO `oc_extension` (`extension_id`, `type`, `code`) VALUES
(23, 'payment', 'cod'),
(22, 'total', 'shipping'),
(57, 'total', 'sub_total'),
(58, 'total', 'tax'),
(59, 'total', 'total'),
(410, 'module', 'banner'),
(426, 'module', 'carousel'),
(390, 'total', 'credit'),
(387, 'shipping', 'flat'),
(349, 'total', 'handling'),
(350, 'total', 'low_order_fee'),
(389, 'total', 'coupon'),
(413, 'module', 'category'),
(408, 'module', 'account'),
(393, 'total', 'reward'),
(398, 'total', 'voucher'),
(407, 'payment', 'free_checkout'),
(427, 'module', 'featured'),
(419, 'module', 'slideshow'),
(428, 'shipping', 'auspost'),
(430, 'module', 'store'),
(431, 'payment', 'pp_pro'),
(432, 'shipping', 'free'),
(433, 'payment', 'pp_standard'),
(434, 'payment', 'pp_express');

-- --------------------------------------------------------

--
-- 表的结构 `oc_filter`
--

CREATE TABLE `oc_filter` (
  `filter_id` int(11) NOT NULL,
  `filter_group_id` int(11) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_filter_description`
--

CREATE TABLE `oc_filter_description` (
  `filter_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `filter_group_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_filter_group`
--

CREATE TABLE `oc_filter_group` (
  `filter_group_id` int(11) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_filter_group_description`
--

CREATE TABLE `oc_filter_group_description` (
  `filter_group_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_geo_zone`
--

CREATE TABLE `oc_geo_zone` (
  `geo_zone_id` int(11) NOT NULL,
  `name` varchar(32) NOT NULL,
  `description` varchar(255) NOT NULL,
  `date_modified` datetime NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_geo_zone`
--

INSERT INTO `oc_geo_zone` (`geo_zone_id`, `name`, `description`, `date_modified`, `date_added`) VALUES
(1, 'Monkey King Thai Restaurant', 'Monkey King Thai Restaurant', '2017-07-03 12:14:10', '2017-04-21 11:59:50');

-- --------------------------------------------------------

--
-- 表的结构 `oc_information`
--

CREATE TABLE `oc_information` (
  `information_id` int(11) NOT NULL,
  `bottom` int(1) NOT NULL DEFAULT '0',
  `sort_order` int(3) NOT NULL DEFAULT '0',
  `status` tinyint(1) NOT NULL DEFAULT '1'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_information`
--

INSERT INTO `oc_information` (`information_id`, `bottom`, `sort_order`, `status`) VALUES
(3, 1, 3, 1),
(4, 1, 1, 1),
(5, 1, 4, 1),
(6, 1, 2, 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_information_description`
--

CREATE TABLE `oc_information_description` (
  `information_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `title` varchar(64) NOT NULL,
  `description` text NOT NULL,
  `meta_title` varchar(255) NOT NULL,
  `meta_description` varchar(255) NOT NULL,
  `meta_keyword` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_information_description`
--

INSERT INTO `oc_information_description` (`information_id`, `language_id`, `title`, `description`, `meta_title`, `meta_description`, `meta_keyword`) VALUES
(4, 1, 'About Us', '&lt;p&gt;\r\n	About Us&lt;/p&gt;\r\n', '', '', ''),
(5, 1, 'Terms &amp; Conditions', '&lt;p&gt;\r\n	Terms &amp;amp; Conditions&lt;/p&gt;\r\n', '', '', ''),
(3, 1, 'Privacy Policy', '&lt;p&gt;\r\n	Privacy Policy&lt;/p&gt;\r\n', '', '', ''),
(6, 1, 'Delivery Information', '&lt;p&gt;\r\n	Delivery Information&lt;/p&gt;\r\n', '', '', '');

-- --------------------------------------------------------

--
-- 表的结构 `oc_information_to_layout`
--

CREATE TABLE `oc_information_to_layout` (
  `information_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL,
  `layout_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_information_to_store`
--

CREATE TABLE `oc_information_to_store` (
  `information_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_information_to_store`
--

INSERT INTO `oc_information_to_store` (`information_id`, `store_id`) VALUES
(3, 0),
(4, 0),
(5, 0),
(6, 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_language`
--

CREATE TABLE `oc_language` (
  `language_id` int(11) NOT NULL,
  `name` varchar(32) NOT NULL,
  `code` varchar(5) NOT NULL,
  `locale` varchar(255) NOT NULL,
  `image` varchar(64) NOT NULL,
  `directory` varchar(32) NOT NULL,
  `sort_order` int(3) NOT NULL DEFAULT '0',
  `status` tinyint(1) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_language`
--

INSERT INTO `oc_language` (`language_id`, `name`, `code`, `locale`, `image`, `directory`, `sort_order`, `status`) VALUES
(1, 'English', 'en', 'en_US.UTF-8,en_US,en-gb,english', 'gb.png', 'english', 1, 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_layout`
--

CREATE TABLE `oc_layout` (
  `layout_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_layout`
--

INSERT INTO `oc_layout` (`layout_id`, `name`) VALUES
(1, 'Home'),
(2, 'Product'),
(3, 'Category'),
(4, 'Default'),
(5, 'Manufacturer'),
(6, 'Account'),
(7, 'Checkout'),
(8, 'Contact'),
(9, 'Sitemap'),
(10, 'Affiliate'),
(11, 'Information'),
(12, 'Compare'),
(13, 'Search');

-- --------------------------------------------------------

--
-- 表的结构 `oc_layout_module`
--

CREATE TABLE `oc_layout_module` (
  `layout_module_id` int(11) NOT NULL,
  `layout_id` int(11) NOT NULL,
  `code` varchar(64) NOT NULL,
  `position` varchar(14) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_layout_module`
--

INSERT INTO `oc_layout_module` (`layout_module_id`, `layout_id`, `code`, `position`, `sort_order`) VALUES
(2, 4, '0', 'content_top', 0),
(3, 4, '0', 'content_top', 1),
(20, 5, '0', 'column_left', 2),
(69, 10, 'affiliate', 'column_right', 1),
(68, 6, 'account', 'column_right', 1),
(67, 1, 'carousel.29', 'content_top', 3),
(66, 1, 'slideshow.27', 'content_top', 1),
(65, 1, 'featured.28', 'content_top', 2),
(72, 3, 'category', 'column_left', 1),
(73, 3, 'banner.30', 'column_left', 2);

-- --------------------------------------------------------

--
-- 表的结构 `oc_layout_route`
--

CREATE TABLE `oc_layout_route` (
  `layout_route_id` int(11) NOT NULL,
  `layout_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL,
  `route` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_layout_route`
--

INSERT INTO `oc_layout_route` (`layout_route_id`, `layout_id`, `store_id`, `route`) VALUES
(38, 6, 0, 'account/%'),
(17, 10, 0, 'affiliate/%'),
(44, 3, 0, 'product/category'),
(42, 1, 0, 'common/home'),
(20, 2, 0, 'product/product'),
(24, 11, 0, 'information/information'),
(23, 7, 0, 'checkout/%'),
(31, 8, 0, 'information/contact'),
(32, 9, 0, 'information/sitemap'),
(34, 4, 0, ''),
(45, 5, 0, 'product/manufacturer'),
(52, 12, 0, 'product/compare'),
(53, 13, 0, 'product/search');

-- --------------------------------------------------------

--
-- 表的结构 `oc_length_class`
--

CREATE TABLE `oc_length_class` (
  `length_class_id` int(11) NOT NULL,
  `value` decimal(15,8) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_length_class`
--

INSERT INTO `oc_length_class` (`length_class_id`, `value`) VALUES
(1, '1.00000000'),
(2, '10.00000000'),
(3, '0.39370000');

-- --------------------------------------------------------

--
-- 表的结构 `oc_length_class_description`
--

CREATE TABLE `oc_length_class_description` (
  `length_class_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `title` varchar(32) NOT NULL,
  `unit` varchar(4) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_length_class_description`
--

INSERT INTO `oc_length_class_description` (`length_class_id`, `language_id`, `title`, `unit`) VALUES
(1, 1, 'Centimeter', 'cm'),
(2, 1, 'Millimeter', 'mm'),
(3, 1, 'Inch', 'in');

-- --------------------------------------------------------

--
-- 表的结构 `oc_location`
--

CREATE TABLE `oc_location` (
  `location_id` int(11) NOT NULL,
  `name` varchar(32) NOT NULL,
  `address` text NOT NULL,
  `telephone` varchar(32) NOT NULL,
  `fax` varchar(32) NOT NULL,
  `geocode` varchar(32) NOT NULL,
  `image` varchar(255) DEFAULT NULL,
  `open` text NOT NULL,
  `comment` text NOT NULL,
  `tag_ids` varchar(25) NOT NULL COMMENT '标签ids',
  `consume` decimal(10,2) NOT NULL DEFAULT '0.00' COMMENT '最低消费',
  `coupon_ids` varchar(25) NOT NULL,
  `geo_zone_id` int(11) NOT NULL DEFAULT '0',
  `isopen` tinyint(1) NOT NULL DEFAULT '1',
  `bgimage` varchar(255) NOT NULL,
  `user_id` int(11) NOT NULL,
  `color` varchar(255) NOT NULL,
  `color1` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_location`
--

INSERT INTO `oc_location` (`location_id`, `name`, `address`, `telephone`, `fax`, `geocode`, `image`, `open`, `comment`, `tag_ids`, `consume`, `coupon_ids`, `geo_zone_id`, `isopen`, `bgimage`, `user_id`, `color`, `color1`) VALUES
(2, '天府川菜馆 Glen Waverley分店', '25 Railway Parade North, Glen Waverley, VIC 3150', '03-9887 8686', '', '', '/groupbuy/public/images/shop_2.png', '', '', '', '0.00', '', 0, 1, '', 0, '', ''),
(1, '天府川菜馆 South Yarra旗舰店', '176 Toorak Road, South Yarra，VIC 3141', '03-9078 1686', '', '', '/groupbuy/public/images/shop_1.png', '', '', '', '0.00', '', 0, 1, '', 0, '', '');

-- --------------------------------------------------------

--
-- 表的结构 `oc_manufacturer`
--

CREATE TABLE `oc_manufacturer` (
  `manufacturer_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL,
  `image` varchar(255) DEFAULT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_manufacturer`
--

INSERT INTO `oc_manufacturer` (`manufacturer_id`, `name`, `image`, `sort_order`) VALUES
(5, 'HTC', 'catalog/demo/htc_logo.jpg', 0),
(6, 'Palm', 'catalog/demo/palm_logo.jpg', 0),
(7, 'Hewlett-Packard', 'catalog/demo/hp_logo.jpg', 0),
(8, 'Apple', 'catalog/demo/apple_logo.jpg', 0),
(9, 'Canon', 'catalog/demo/canon_logo.jpg', 0),
(10, 'Sony', 'catalog/demo/sony_logo.jpg', 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_manufacturer_to_store`
--

CREATE TABLE `oc_manufacturer_to_store` (
  `manufacturer_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_manufacturer_to_store`
--

INSERT INTO `oc_manufacturer_to_store` (`manufacturer_id`, `store_id`) VALUES
(5, 0),
(6, 0),
(7, 0),
(8, 0),
(9, 0),
(10, 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_marketing`
--

CREATE TABLE `oc_marketing` (
  `marketing_id` int(11) NOT NULL,
  `name` varchar(32) NOT NULL,
  `description` text NOT NULL,
  `code` varchar(64) NOT NULL,
  `clicks` int(5) NOT NULL DEFAULT '0',
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_modification`
--

CREATE TABLE `oc_modification` (
  `modification_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL,
  `code` varchar(64) NOT NULL,
  `author` varchar(64) NOT NULL,
  `version` varchar(32) NOT NULL,
  `link` varchar(255) NOT NULL,
  `xml` text NOT NULL,
  `status` tinyint(1) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_module`
--

CREATE TABLE `oc_module` (
  `module_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL,
  `code` varchar(32) NOT NULL,
  `setting` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_module`
--

INSERT INTO `oc_module` (`module_id`, `name`, `code`, `setting`) VALUES
(30, 'Category', 'banner', 'a:5:{s:4:\"name\";s:17:\"Banner - Category\";s:9:\"banner_id\";s:1:\"6\";s:5:\"width\";s:3:\"300\";s:6:\"height\";s:3:\"300\";s:6:\"status\";s:1:\"1\";}'),
(29, 'Home Page', 'carousel', 'a:5:{s:4:\"name\";s:20:\"Carousel - Home Page\";s:9:\"banner_id\";s:1:\"8\";s:5:\"width\";s:3:\"130\";s:6:\"height\";s:3:\"100\";s:6:\"status\";s:1:\"1\";}'),
(28, 'Home Page', 'featured', 'a:6:{s:4:\"name\";s:20:\"Featured - Home Page\";s:7:\"product\";a:4:{i:0;s:2:\"43\";i:1;s:2:\"40\";i:2;s:2:\"42\";i:3;s:2:\"30\";}s:5:\"limit\";s:1:\"4\";s:5:\"width\";s:3:\"200\";s:6:\"height\";s:3:\"200\";s:6:\"status\";s:1:\"1\";}'),
(27, 'Home Page', 'slideshow', 'a:5:{s:4:\"name\";s:21:\"Slideshow - Home Page\";s:9:\"banner_id\";s:1:\"7\";s:5:\"width\";s:4:\"1140\";s:6:\"height\";s:3:\"380\";s:6:\"status\";s:1:\"1\";}');

-- --------------------------------------------------------

--
-- 表的结构 `oc_option`
--

CREATE TABLE `oc_option` (
  `option_id` int(11) NOT NULL,
  `type` varchar(32) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_option`
--

INSERT INTO `oc_option` (`option_id`, `type`, `sort_order`) VALUES
(1, 'radio', 0),
(2, 'radio', 0),
(3, 'radio', 0),
(4, 'radio', 4),
(5, 'radio', 5);

-- --------------------------------------------------------

--
-- 表的结构 `oc_option_description`
--

CREATE TABLE `oc_option_description` (
  `option_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_option_description`
--

INSERT INTO `oc_option_description` (`option_id`, `language_id`, `name`) VALUES
(2, 1, 'extra noodle'),
(1, 1, 'extra egg'),
(2, 2, '加面'),
(1, 2, '加蛋');

-- --------------------------------------------------------

--
-- 表的结构 `oc_option_value`
--

CREATE TABLE `oc_option_value` (
  `option_value_id` int(11) NOT NULL,
  `option_id` int(11) NOT NULL,
  `image` varchar(255) NOT NULL,
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_option_value`
--

INSERT INTO `oc_option_value` (`option_value_id`, `option_id`, `image`, `sort_order`) VALUES
(2, 1, '', 2),
(1, 1, '', 1),
(5, 2, '', 3),
(4, 2, '', 2),
(3, 2, '', 1),
(7, 3, '', 2),
(6, 3, '', 1),
(8, 4, '', 8),
(9, 4, '', 9),
(10, 4, '', 10),
(11, 4, '', 11),
(12, 4, '', 12),
(13, 4, '', 13),
(14, 4, '', 14),
(15, 4, '', 15),
(16, 4, '', 16),
(17, 4, '', 17),
(18, 4, '', 18),
(19, 5, '', 19),
(20, 5, '', 20),
(21, 5, '', 21),
(22, 5, '', 22),
(23, 5, '', 23),
(24, 5, '', 24),
(25, 5, '', 25),
(26, 5, '', 26),
(27, 5, '', 27),
(28, 5, '', 28),
(29, 5, '', 29),
(30, 5, '', 30);

-- --------------------------------------------------------

--
-- 表的结构 `oc_option_value_description`
--

CREATE TABLE `oc_option_value_description` (
  `option_value_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `option_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_option_value_description`
--

INSERT INTO `oc_option_value_description` (`option_value_id`, `language_id`, `option_id`, `name`) VALUES
(3, 1, 2, 'extra noodle'),
(3, 2, 2, '加面'),
(2, 1, 1, 'fried egg'),
(2, 2, 1, '煎蛋'),
(1, 2, 1, '煮蛋'),
(1, 1, 1, 'braised egg');

-- --------------------------------------------------------

--
-- 表的结构 `oc_order`
--

CREATE TABLE `oc_order` (
  `order_id` int(11) NOT NULL,
  `invoice_no` int(11) NOT NULL DEFAULT '0',
  `invoice_prefix` varchar(26) NOT NULL,
  `store_id` int(11) NOT NULL DEFAULT '0',
  `store_name` varchar(64) NOT NULL,
  `store_url` varchar(255) NOT NULL,
  `customer_id` int(11) NOT NULL DEFAULT '0',
  `customer_group_id` int(11) NOT NULL DEFAULT '0',
  `firstname` varchar(32) NOT NULL,
  `lastname` varchar(32) NOT NULL,
  `email` varchar(96) NOT NULL,
  `telephone` varchar(32) NOT NULL,
  `fax` varchar(32) NOT NULL,
  `custom_field` text NOT NULL,
  `payment_firstname` varchar(32) NOT NULL,
  `payment_lastname` varchar(32) NOT NULL,
  `payment_company` varchar(40) NOT NULL,
  `payment_address_1` varchar(128) NOT NULL,
  `payment_address_2` varchar(128) NOT NULL,
  `payment_city` varchar(128) NOT NULL,
  `payment_postcode` varchar(10) NOT NULL,
  `payment_country` varchar(128) NOT NULL,
  `payment_country_id` int(11) NOT NULL,
  `payment_state` varchar(128) NOT NULL,
  `payment_state_id` int(11) NOT NULL,
  `payment_suburb` varchar(128) NOT NULL,
  `payment_suburb_id` int(11) NOT NULL,
  `payment_address_format` text NOT NULL,
  `payment_custom_field` text NOT NULL,
  `payment_method` varchar(128) NOT NULL,
  `payment_code` varchar(128) NOT NULL,
  `shipping_firstname` varchar(32) NOT NULL,
  `shipping_lastname` varchar(32) NOT NULL,
  `shipping_email` varchar(255) NOT NULL,
  `shipping_telephone` varchar(255) NOT NULL,
  `shipping_company` varchar(40) NOT NULL,
  `shipping_address_1` varchar(128) NOT NULL,
  `shipping_address_2` varchar(128) NOT NULL,
  `shipping_city` varchar(128) NOT NULL,
  `shipping_postcode` varchar(10) NOT NULL,
  `shipping_country` varchar(128) NOT NULL,
  `shipping_country_id` int(11) NOT NULL,
  `shipping_state` varchar(128) NOT NULL,
  `shipping_state_id` int(11) NOT NULL,
  `shipping_suburb` varchar(128) NOT NULL,
  `shipping_suburb_id` int(11) NOT NULL,
  `shipping_address_format` text NOT NULL,
  `shipping_custom_field` text NOT NULL,
  `shipping_method` varchar(128) NOT NULL,
  `shipping_orderTime` varchar(128) NOT NULL,
  `shipping_orderDate` varchar(128) NOT NULL,
  `shipping_orderWhen` varchar(128) NOT NULL,
  `shipping_code` varchar(128) NOT NULL,
  `comment` text NOT NULL,
  `total` decimal(15,4) NOT NULL DEFAULT '0.0000',
  `order_status_id` int(11) NOT NULL DEFAULT '0',
  `affiliate_id` int(11) NOT NULL,
  `commission` decimal(15,4) NOT NULL,
  `marketing_id` int(11) NOT NULL,
  `tracking` varchar(64) NOT NULL,
  `language_id` int(11) NOT NULL,
  `currency_id` int(11) NOT NULL,
  `currency_code` varchar(3) NOT NULL,
  `currency_value` decimal(15,8) NOT NULL DEFAULT '1.00000000',
  `ip` varchar(40) NOT NULL,
  `forwarded_ip` varchar(40) NOT NULL,
  `user_agent` varchar(255) NOT NULL,
  `accept_language` varchar(255) NOT NULL,
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_order`
--

INSERT INTO `oc_order` (`order_id`, `invoice_no`, `invoice_prefix`, `store_id`, `store_name`, `store_url`, `customer_id`, `customer_group_id`, `firstname`, `lastname`, `email`, `telephone`, `fax`, `custom_field`, `payment_firstname`, `payment_lastname`, `payment_company`, `payment_address_1`, `payment_address_2`, `payment_city`, `payment_postcode`, `payment_country`, `payment_country_id`, `payment_state`, `payment_state_id`, `payment_suburb`, `payment_suburb_id`, `payment_address_format`, `payment_custom_field`, `payment_method`, `payment_code`, `shipping_firstname`, `shipping_lastname`, `shipping_email`, `shipping_telephone`, `shipping_company`, `shipping_address_1`, `shipping_address_2`, `shipping_city`, `shipping_postcode`, `shipping_country`, `shipping_country_id`, `shipping_state`, `shipping_state_id`, `shipping_suburb`, `shipping_suburb_id`, `shipping_address_format`, `shipping_custom_field`, `shipping_method`, `shipping_orderTime`, `shipping_orderDate`, `shipping_orderWhen`, `shipping_code`, `comment`, `total`, `order_status_id`, `affiliate_id`, `commission`, `marketing_id`, `tracking`, `language_id`, `currency_id`, `currency_code`, `currency_value`, `ip`, `forwarded_ip`, `user_agent`, `accept_language`, `date_added`, `date_modified`) VALUES
(1, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '20:30', 'Tue, 1 Aug 17', 'later', '', '', '93.7000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-01 17:18:48', '2017-08-01 17:18:48'),
(2, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 13, 1, '', '', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '19:00', 'Tue, 1 Aug 17', 'later', '', '', '10.0000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-01 17:23:34', '2017-08-01 17:23:34'),
(3, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 13, 1, '', '', 'haLi@gmail.com', '0430120999', '', '', 'ha', 'Li', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'ha', 'Li', 'haLi@gmail.com', '0430120999', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '19:15', 'Tue, 1 Aug 17', 'later', '', '', '25.8000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-01 17:35:14', '2017-08-01 17:35:14'),
(4, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'c@gmail.com', '0430120999', '', '', 'a', 'b', '', 's2', 'sn', '', '', 'Australia', 1, 'New South Wales', 2, 'East Killara', 8, '', '', 'Cash', 'cod', 'a', 'b', 'c@gmail.com', '0430120999', '', 's2', 'sn', '', '', 'Australia', 1, 'New South Wales', 2, 'East Killara', 8, '', '', 'Delivery', '14:45', 'Wed, 2 Aug 17', 'later', '', 'test', '21.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-02 11:07:52', '2017-08-02 11:07:52'),
(5, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120999', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120999', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '18:00', 'Wed, 2 Aug 17', 'later', '', '', '39.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-02 15:26:14', '2017-08-02 15:26:14'),
(6, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120999', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120999', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '18:00', 'Wed, 2 Aug 17', 'later', '', '', '19.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-02 15:33:00', '2017-08-02 15:33:00'),
(7, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120999', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120999', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '18:00', 'Wed, 2 Aug 17', 'later', '', '', '39.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-02 15:39:38', '2017-08-02 15:39:38'),
(8, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', 'a', 'badafdsa', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '22:15', 'Fri, 4 Aug 17', 'later', '', 's', '10.0000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-04 11:38:40', '2017-08-04 11:38:40'),
(9, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', 'a', 'badafdsa', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'PayPal', 'pp_standard', 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '21:45', 'Fri, 4 Aug 17', 'later', '', 's', '12.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-04 11:39:16', '2017-08-04 11:39:16'),
(10, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', 'a', 'badafdsa', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'PayPal', 'pp_standard', 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '21:45', 'Fri, 4 Aug 17', 'later', '', 's', '25.8000', 0, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-04 12:02:15', '2017-08-04 12:02:15'),
(11, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', 'a', 'badafdsa', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '21:45', 'Fri, 4 Aug 17', 'later', '', 's', '43.7000', 4, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-04 12:02:48', '2017-08-04 12:02:48'),
(12, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', 'a', 'badafdsa', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'badafdsa', 'c@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '21:45', 'Fri, 4 Aug 17', 'later', '', 's', '16.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-04 12:14:57', '2017-08-04 12:14:57'),
(13, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Wed, 9 Aug 17', 'later', '', '', '19.9000', 4, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-09 12:26:36', '2017-08-09 12:26:37'),
(14, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:30', 'Wed, 9 Aug 17', 'later', '', '', '26.9000', 4, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-09 12:32:38', '2017-08-09 12:32:38'),
(15, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '19:30', 'Wed, 9 Aug 17', 'later', '', '', '17.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-09 12:34:15', '2017-08-09 12:34:15'),
(16, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'PayPal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '12:45', 'Thu, 10 Aug 17', 'later', '', '', '10.0000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-10 11:52:12', '2017-08-10 11:52:12'),
(17, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Wed, 16 Aug 17', 'later', '', '', '29.8000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-16 17:50:48', '2017-08-16 17:50:48'),
(18, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:30', 'Wed, 16 Aug 17', 'later', '', '', '27.8000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-16 17:58:02', '2017-08-16 17:58:02'),
(19, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', 'a', 'b1', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', 'a', 'b1', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Delivery', '16:00', 'Wed, 16 Aug 17', 'later', '', '', '20.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-16 18:23:56', '2017-08-16 18:23:56'),
(20, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '22:00', 'Thu, 17 Aug 17', 'later', '', '', '10.0000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-17 10:35:36', '2017-08-17 10:35:37'),
(21, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', 'a', 'absd', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', 'a', 'absd', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'Delivery', '21:30', 'Thu, 17 Aug 17', 'later', '', 'deli', '22.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-17 10:41:40', '2017-08-17 10:41:40'),
(22, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '13:30', 'Tue, 22 Aug 17', 'later', '', '', '30.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-22 13:18:58', '2017-08-22 13:18:58'),
(23, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '13:30', 'Tue, 22 Aug 17', 'later', '', '', '21.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-22 13:20:35', '2017-08-22 13:20:35'),
(24, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '13:30', 'Tue, 22 Aug 17', 'later', '', '', '39.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-22 14:00:25', '2017-08-22 14:00:26'),
(25, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 's', 's', 's@163.com', '0430120888', '', '', 's', 's', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 's', 's', 's@163.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '23:15', 'Wed, 30 Aug 17', 'later', '', '', '26.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-25 16:50:44', '2017-08-25 16:50:44'),
(26, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 's', 's', 's@163.com', '0430120888', '', '', 's', 's', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 's', 's', 's@163.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '23:15', 'Wed, 30 Aug 17', 'later', '', '', '109.3000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-25 16:57:07', '2017-08-25 16:57:07'),
(27, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 's', 's', 's@163.com', '0430120888', '', '', 's', 's', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 's', 's', 's@163.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '23:15', 'Wed, 30 Aug 17', 'later', '', 'test', '13.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-25 16:59:16', '2017-08-25 16:59:16'),
(28, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 's', 's', 's@163.com', '0430120888', '', '', 's', 's', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 's', 's', 's@163.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '23:15', 'Wed, 30 Aug 17', 'later', '', 'test', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-25 17:43:04', '2017-08-25 17:43:04'),
(29, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 's', 's', 's@163.com', '0430120888', '', '', 's', 's', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 's', 's', 's@163.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '23:15', 'Wed, 30 Aug 17', 'later', '', 'test', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-25 18:01:16', '2017-08-25 18:01:16'),
(30, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'b', 'a@gmail.com', '0430120888', '', '', 'a2', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Tue, 29 Aug 17', 'later', '', '', '19.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-28 15:56:11', '2017-08-28 15:56:11'),
(31, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'b', 'a@gmail.com', '0430120888', '', '', 'a2', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Tue, 29 Aug 17', 'later', '', '', '11.0000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-28 16:08:49', '2017-08-28 16:08:49'),
(32, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'b', 'a@gmail.com', '0430120888', '', '', 'a2', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Tue, 29 Aug 17', 'later', '', '', '10.0000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-29 17:13:55', '2017-08-29 17:13:55'),
(33, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'b', 'a@gmail.com', '0430120888', '', '', 'a2', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Tue, 29 Aug 17', 'later', '', 't', '17.7000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-29 17:49:54', '2017-08-29 17:49:54'),
(34, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'b', 'a@gmail.com', '0430120888', '', '', 'a2', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Tue, 29 Aug 17', 'later', '', 't2', '30.0000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-08-29 17:52:08', '2017-08-29 17:52:08'),
(35, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '13:15', 'Thu, 7 Sep 17', 'later', '', '', '19.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 16:36:19', '2017-09-07 16:36:19'),
(36, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:30', 'Thu, 7 Sep 17', 'later', '', '', '12.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 17:02:35', '2017-09-07 17:02:35'),
(37, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:30', 'Thu, 7 Sep 17', 'later', '', '', '17.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 17:06:53', '2017-09-07 17:06:53'),
(38, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:30', 'Thu, 7 Sep 17', 'later', '', '', '12.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 17:11:07', '2017-09-07 17:11:07'),
(39, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:30', 'Thu, 7 Sep 17', 'later', '', '', '19.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 17:11:54', '2017-09-07 17:11:54'),
(40, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:30', 'Thu, 7 Sep 17', 'later', '', '', '20.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 17:19:02', '2017-09-07 17:19:02'),
(41, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test', '35.8000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 17:58:27', '2017-09-07 17:58:27'),
(42, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test', '19.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:04:43', '2017-09-07 18:04:43'),
(43, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test', '62.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:13:37', '2017-09-07 18:13:37'),
(44, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test', '62.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:23:54', '2017-09-07 18:23:54'),
(45, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test', '62.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:29:41', '2017-09-07 18:29:41'),
(46, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test2', '19.8000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:34:45', '2017-09-07 18:34:45'),
(47, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test2', '11.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:41:21', '2017-09-07 18:41:21'),
(48, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test2', '28.7000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:43:08', '2017-09-07 18:43:08'),
(49, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test2', '36.7000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:45:13', '2017-09-07 18:45:13'),
(50, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test2', '19.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:51:54', '2017-09-07 18:51:54'),
(51, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test2', '19.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:53:38', '2017-09-07 18:53:38'),
(52, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '17:30', 'Thu, 7 Sep 17', 'later', '', 'test2', '20.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-07 18:55:53', '2017-09-07 18:55:53'),
(53, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '23:00', 'Fri, 8 Sep 17', 'later', '', '', '28.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-08 10:41:12', '2017-09-08 10:41:12'),
(54, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '23:00', 'Fri, 8 Sep 17', 'later', '', '', '19.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-08 10:50:19', '2017-09-08 10:50:20'),
(55, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '23:00', 'Fri, 8 Sep 17', 'later', '', '', '15.0000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-08 10:53:57', '2017-09-08 10:53:57'),
(56, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Wed, 13 Sep 17', 'later', '', '', '16.9000', 4, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-13 15:29:05', '2017-09-13 15:29:06'),
(57, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Wed, 13 Sep 17', 'later', '', '', '10.0000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-13 16:11:16', '2017-09-13 16:11:16'),
(58, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Wed, 13 Sep 17', 'later', '', '', '16.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-13 16:16:42', '2017-09-13 16:16:42'),
(59, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Wed, 13 Sep 17', 'later', '', '', '10.0000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-13 16:18:58', '2017-09-13 16:18:58'),
(60, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Wed, 13 Sep 17', 'later', '', '', '17.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-13 16:23:12', '2017-09-13 16:23:12'),
(61, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Wed, 13 Sep 17', 'later', '', '', '17.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-13 16:24:54', '2017-09-13 16:24:54'),
(62, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Wed, 13 Sep 17', 'later', '', '', '18.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-13 16:25:34', '2017-09-13 16:25:34'),
(63, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Wed, 13 Sep 17', 'later', '', '', '12.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-13 16:58:51', '2017-09-13 16:58:51'),
(64, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'b', 'a@gmail.com', '0430120888', '', '', 'a2', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Thu, 14 Sep 17', 'later', '', '', '10.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-14 13:55:37', '2017-09-14 13:55:37'),
(65, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Wed, 20 Sep 17', 'later', '', 'a', '12.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-20 11:07:17', '2017-09-20 11:07:17'),
(66, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Wed, 20 Sep 17', 'later', '', 'a', '17.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-20 11:15:15', '2017-09-20 11:15:15'),
(67, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:00', 'Thu, 28 Sep 17', 'later', '', '', '12.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-28 14:38:14', '2017-09-28 14:38:14'),
(68, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '22:15', 'Fri, 29 Sep 17', 'later', '', '', '22.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 18:41:07', '2017-09-29 18:41:08'),
(69, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '22:15', 'Fri, 29 Sep 17', 'later', '', '', '12.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 18:54:59', '2017-09-29 18:54:59'),
(70, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '22:15', 'Fri, 29 Sep 17', 'later', '', '', '39.8000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:00:45', '2017-09-29 19:00:45'),
(71, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '22:15', 'Fri, 29 Sep 17', 'later', '', '', '16.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:04:54', '2017-09-29 19:04:54'),
(72, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', 'a', 'b', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'PayPal', 'pp_standard', 'a', 'b', 'a@gmail.com', '0430120888', '', 'a', 'b', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'Delivery', '22:15', 'Fri, 29 Sep 17', 'later', '', 'sad', '17.9000', 0, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:11:31', '2017-09-29 19:11:31'),
(73, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', 'a', 'b', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', 'a', 'b', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'Delivery', '22:15', 'Fri, 29 Sep 17', 'later', '', 'sad', '17.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:11:39', '2017-09-29 19:11:39'),
(74, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '22:15', 'Fri, 29 Sep 17', 'later', '', 'sad', '26.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:17:28', '2017-09-29 19:17:28'),
(75, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '12', 's1', '', '', 'Australia', 1, 'New South Wales', 2, 'Gordon', 9, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '12', 's1', '', '', 'Australia', 1, 'New South Wales', 2, 'Gordon', 9, '', '', 'Delivery', '21:15', 'Fri, 29 Sep 17', 'later', '', 'sad', '22.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:20:23', '2017-09-29 19:20:23'),
(76, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '21:15', 'Fri, 29 Sep 17', 'later', '', 'sad', '41.8000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:28:43', '2017-09-29 19:28:43'),
(77, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '1', 's1', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '1', 's1', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'Delivery', '21:15', 'Fri, 29 Sep 17', 'later', '', ' ', '29.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:32:39', '2017-09-29 19:32:39');
INSERT INTO `oc_order` (`order_id`, `invoice_no`, `invoice_prefix`, `store_id`, `store_name`, `store_url`, `customer_id`, `customer_group_id`, `firstname`, `lastname`, `email`, `telephone`, `fax`, `custom_field`, `payment_firstname`, `payment_lastname`, `payment_company`, `payment_address_1`, `payment_address_2`, `payment_city`, `payment_postcode`, `payment_country`, `payment_country_id`, `payment_state`, `payment_state_id`, `payment_suburb`, `payment_suburb_id`, `payment_address_format`, `payment_custom_field`, `payment_method`, `payment_code`, `shipping_firstname`, `shipping_lastname`, `shipping_email`, `shipping_telephone`, `shipping_company`, `shipping_address_1`, `shipping_address_2`, `shipping_city`, `shipping_postcode`, `shipping_country`, `shipping_country_id`, `shipping_state`, `shipping_state_id`, `shipping_suburb`, `shipping_suburb_id`, `shipping_address_format`, `shipping_custom_field`, `shipping_method`, `shipping_orderTime`, `shipping_orderDate`, `shipping_orderWhen`, `shipping_code`, `comment`, `total`, `order_status_id`, `affiliate_id`, `commission`, `marketing_id`, `tracking`, `language_id`, `currency_id`, `currency_code`, `currency_value`, `ip`, `forwarded_ip`, `user_agent`, `accept_language`, `date_added`, `date_modified`) VALUES
(78, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '1', 's1', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '1', 's1', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'Delivery', '21:15', 'Fri, 29 Sep 17', 'later', '', ' ', '29.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:35:49', '2017-09-29 19:35:49'),
(79, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '1', 's1', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '1', 's1', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'Delivery', '21:15', 'Fri, 29 Sep 17', 'later', '', ' ', '20.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:51:39', '2017-09-29 19:51:39'),
(80, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '21:15', 'Fri, 29 Sep 17', 'later', '', ' ', '17.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 19:58:04', '2017-09-29 19:58:04'),
(81, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '3', 's3', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '3', 's3', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Delivery', '21:15', 'Fri, 29 Sep 17', 'later', '', ' ', '31.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 20:00:19', '2017-09-29 20:00:19'),
(82, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '3', 's3', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '3', 's3', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Delivery', '21:15', 'Fri, 29 Sep 17', 'later', '', ' ', '15.0000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 20:02:21', '2017-09-29 20:02:21'),
(83, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '3', 's3', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '3', 's3', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Delivery', '21:15', 'Fri, 29 Sep 17', 'later', '', ' ', '22.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 20:06:19', '2017-09-29 20:06:19'),
(84, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '21:15', 'Fri, 29 Sep 17', 'later', '', ' ', '26.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5376e Safari/8536.25', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-09-29 20:07:35', '2017-09-29 20:07:35'),
(85, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '19:45', 'Tue, 3 Oct 17', 'later', '', '', '16.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-03 10:01:56', '2017-10-03 10:01:56'),
(86, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '2', 's3', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '2', 's3', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Delivery', '07:30', 'Tue, 3 Oct 17', 'later', '', 't', '22.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-03 10:05:34', '2017-10-03 10:05:34'),
(87, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '19:15', 'Tue, 3 Oct 17', 'later', '', 't', '26.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-03 10:08:24', '2017-10-03 10:08:24'),
(88, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '16:15', 'Tue, 3 Oct 17', 'later', '', 't', '12.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-03 10:17:50', '2017-10-03 10:17:50'),
(89, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '1', 's33', '', '', 'Australia', 1, 'New South Wales', 2, 'Gordon', 9, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '1', 's33', '', '', 'Australia', 1, 'New South Wales', 2, 'Gordon', 9, '', '', 'Delivery', '20:45', 'Tue, 3 Oct 17', 'later', '', 't', '17.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-03 10:19:12', '2017-10-03 10:19:12'),
(90, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '1', 's33', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '1', 's33', '', '', 'Australia', 1, 'New South Wales', 2, 'Killara', 3, '', '', 'Delivery', '20:45', 'Tue, 3 Oct 17', 'later', '', 't', '20.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-03 10:22:53', '2017-10-03 10:22:53'),
(91, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '21:15', 'Tue, 3 Oct 17', 'later', '', 't', '10.0000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-03 10:31:27', '2017-10-03 10:31:27'),
(92, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'badafdsa', 'a@gmail.com', '0430120888', '', '', 'a', 'badafdsa', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'badafdsa', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '22:30', 'Fri, 20 Oct 17', 'later', '', '', '16.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-20 11:43:01', '2017-10-20 11:43:01'),
(93, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'a3', 'a@gmail.com', '0430120888', '', '', 'a2', 'a3', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'a3', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '09:45', 'Mon, 23 Oct 17', 'later', '', '', '16.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-23 12:50:40', '2017-10-23 12:50:41'),
(94, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'a3', 'a@gmail.com', '0430120888', '', '', 'a2', 'a3', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'a3', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '09:45', 'Mon, 23 Oct 17', 'later', '', '', '10.0000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-23 12:52:29', '2017-10-23 12:52:29'),
(95, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'a3', 'a@gmail.com', '0430120888', '', '', 'a2', 'a3', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'a3', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '09:45', 'Mon, 23 Oct 17', 'later', '', '', '17.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-23 12:54:11', '2017-10-23 12:54:11'),
(96, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a2', 'a3', 'a@gmail.com', '0430120888', '', '', 'a2', 'a3', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a2', 'a3', 'a@gmail.com', '0430120888', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '09:45', 'Mon, 23 Oct 17', 'later', '', '', '22.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-23 12:55:58', '2017-10-23 12:55:58'),
(97, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120999', '', '', 'a', 'b', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120999', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '08:15', 'Tue, 24 Oct 17', 'later', '', '', '16.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-24 11:11:31', '2017-10-24 11:11:31'),
(98, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120999', '', '', 'a', 'b', '', 's1', 's', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120999', '', 's1', 's', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Delivery', '10:00', 'Tue, 24 Oct 17', 'later', '', 'delivery', '22.9000', 3, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-10-24 12:24:14', '2017-10-24 12:24:14'),
(99, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'test', 'test', 'test@16.com', '05534535', '', '', 'test', 'test', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'test', 'test', 'test@16.com', '05534535', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '03:45', 'Fri, 17 Nov 17', 'later', '', 't', '16.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-11-17 12:03:56', '2017-11-17 12:03:56'),
(100, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'test', 'test', 'test@16.com', '05534535', '', '', 'test', 'test', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'PayPal', 'pp_standard', 'test', 'test', 'test@16.com', '05534535', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '03:45', 'Fri, 17 Nov 17', 'later', '', 't', '22.9000', 0, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-11-17 12:10:00', '2017-11-17 12:10:00'),
(101, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'test', 'test', 'test@16.com', '05534535', '', '', 'test', 'test', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'test', 'test', 'test@16.com', '05534535', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '03:45', 'Fri, 17 Nov 17', 'later', '', 't', '22.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-11-17 12:10:17', '2017-11-17 12:10:17'),
(102, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'test', 'test', 'test@16.com', '05534535', '', '', 'test', 'test', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'paypal', 'cod', 'test', 'test', 'test@16.com', '05534535', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '04:15', 'Fri, 17 Nov 17', 'later', '', 't', '20.9000', 2, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-11-17 12:12:46', '2017-11-17 12:12:46'),
(103, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'test', 'test', 'test@16.com', '05534535', '', '', 'test', 'test', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 'test', 'test', 'test@16.com', '05534535', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '04:00', 'Fri, 17 Nov 17', 'later', '', 't', '22.9000', 4, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-11-17 12:19:55', '2017-11-17 12:19:55'),
(104, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 's', 's', 's@163.com', '043088', '', '', 's', 's', '', 'a', 'd', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', 's', 's', 's@163.com', '043088', '', 'a', 'd', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Delivery', '10:30', 'Fri, 17 Nov 17', 'later', '', 's', '23.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-11-17 18:39:33', '2017-11-17 18:39:33'),
(105, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 's', 's', 's@163.com', '043088', '', '', 's', 's', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Cash', 'cod', 's', 's', 's@163.com', '043088', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'Pick-up', '10:15', 'Fri, 17 Nov 17', 'later', '', 's', '14.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2017-11-17 18:42:50', '2017-11-17 18:42:50'),
(106, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120999', '', '', 'a', 'b', '', 'a', 'a', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120999', '', 'a', 'a', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Delivery', '00:45', 'Wed 10 Jan ', 'now', '', 'sd', '21.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-10 12:09:33', '2018-01-10 12:09:34'),
(107, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'f', 'a', 'a@gmail.com', '0430120888', '', '', 'f', 'a', '', 'a', '3', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'Cash', 'cod', 'f', 'a', 'a@gmail.com', '0430120888', '', 'a', '3', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'Delivery', '00:45', 'Fri 12 Jan ', 'now', '', '', '24.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-12 12:38:15', '2018-01-12 12:38:15'),
(108, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'f', 'a', 'a@gmail.com', '0430120888', '', '', 'f', 'a', '', 'a', '3', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'Cash', 'cod', 'f', 'a', 'a@gmail.com', '0430120888', '', 'a', '3', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'Delivery', '00:45', 'Fri 12 Jan ', 'now', '', '', '31.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-12 12:40:12', '2018-01-12 12:40:12'),
(109, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', 'a', 'a', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', 'a', 'a', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Delivery', '00:45', 'Wed 17 Jan ', 'now', '', 'b', '45.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-17 14:13:26', '2018-01-17 14:13:27'),
(110, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', 'a', 'a', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', 'a', 'a', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Delivery', '00:45', 'Wed 17 Jan ', 'now', '', 'b', '45.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-17 14:21:10', '2018-01-17 14:21:10'),
(111, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'b', 'a@gmail.com', '0430120888', '', '', 'a', 'b', '', 'a', 'a', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', 'a', 'b', 'a@gmail.com', '0430120888', '', 'a', 'a', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Delivery', '00:45', 'Wed 17 Jan ', 'now', '', 'b', '45.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-17 14:22:27', '2018-01-17 14:22:27'),
(112, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, 'a', 'a', 'a@gmail.com', '0430120888', '', '', 'a', 'a', '', 'a', 'b', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Cash', 'cod', 'a', 'a', 'a@gmail.com', '0430120888', '', 'a', 'b', '', '', 'Australia', 1, 'New South Wales', 2, 'East Lindfield', 6, '', '', 'Delivery', '00:45', 'Fri 19 Jan ', 'now', '', '', '23.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 15:51:33', '2018-01-19 15:51:33'),
(113, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', '', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'East Killara', 8, '', '', 'Cash', 'cod', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'East Killara', 8, '', '', 'Delivery', '00:45', 'Fri 19 Jan ', 'now', '', '', '31.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 15:58:11', '2018-01-19 15:58:11'),
(114, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', '', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'Cash', 'cod', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood', 4, '', '', 'Delivery', '00:45', 'Fri 19 Jan ', 'now', '', '', '16.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 16:00:03', '2018-01-19 16:00:03'),
(115, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', '', '', 'dumpnull@a.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Delivery', '00:45', 'Fri 19 Jan ', 'now', '', '', '32.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 16:02:07', '2018-01-19 16:02:07'),
(116, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Fri 19 Jan ', 'now', '', '', '30.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 16:13:28', '2018-01-19 16:13:28'),
(117, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'Cash', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Fri 19 Jan ', 'now', '', '', '16.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 16:19:07', '2018-01-19 16:19:07'),
(118, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Fri 19 Jan ', 'now', '', '', '16.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 16:23:46', '2018-01-19 16:23:46'),
(119, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', 'pp_standard', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Fri 19 Jan ', 'now', '', '', '30.9000', 0, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 16:29:01', '2018-01-19 16:29:01'),
(120, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Fri 19 Jan ', 'now', '', '', '30.9000', 0, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 16:29:49', '2018-01-19 16:29:49'),
(121, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Fri 19 Jan ', 'now', '', '', '30.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-19 16:30:36', '2018-01-19 16:30:36'),
(122, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Mon 22 Jan ', 'now', '', '', '16.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 12:50:21', '2018-01-22 12:50:22'),
(123, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Mon 22 Jan ', 'now', '', '', '26.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 12:51:20', '2018-01-22 12:51:20'),
(124, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Mon 22 Jan ', 'now', '', '', '22.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 12:52:41', '2018-01-22 12:52:41'),
(125, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', 'Australia', 1, 'New South Wales', 2, 'Chatswood West', 2, '', '', 'DineIn', '00:45', 'Mon 22 Jan ', 'now', '', '', '22.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 12:58:46', '2018-01-22 12:58:46'),
(126, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:45', 'Mon 22 Jan ', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 13:47:33', '2018-01-22 13:47:33'),
(127, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Mon 22 Jan ', 'now', '', '', '18.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 15:12:19', '2018-01-22 15:12:19'),
(128, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Mon 22 Jan ', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 15:12:42', '2018-01-22 15:12:42'),
(129, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Mon 22 Jan ', 'now', '', '', '18.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 15:13:24', '2018-01-22 15:13:24'),
(130, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Mon 22 Jan ', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 15:14:44', '2018-01-22 15:14:44'),
(131, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Mon 22 Jan ', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 15:18:15', '2018-01-22 15:18:15'),
(132, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Mon 22 Jan ', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-22 15:31:30', '2018-01-22 15:31:30'),
(133, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Wed 24 Jan ', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.246', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0_3 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A432 Safari/604.1', 'zh-cn', '2018-01-24 20:04:04', '2018-01-24 20:04:04'),
(134, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Wed 24 Jan ', 'now', '', '', '17.8000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.246', '', 'Mozilla/5.0 (iPhone; CPU iPhone OS 11_0_3 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A432 Safari/604.1', 'zh-cn', '2018-01-24 20:07:00', '2018-01-24 20:07:00'),
(135, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Thu 25 Jan ', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.209', '', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/63.0.3239.132 Safari/537.36', 'en-US,en;q=0.9', '2018-01-25 12:22:06', '2018-01-25 12:22:06'),
(136, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Thu 25 Jan 18', 'now', '', '', '26.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-25 13:04:25', '2018-01-25 13:04:25'),
(137, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Thu, 25 Jan 2018', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-25 13:23:02', '2018-01-25 13:23:02'),
(138, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Thu, 25 Jan 18', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-25 13:24:38', '2018-01-25 13:24:38'),
(139, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Thu, 25 Jan 18', 'now', '', '', '10.9000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-25 14:22:20', '2018-01-25 14:22:20'),
(140, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'dumpnull@a2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Thu, 25 Jan 18', 'now', '', '', '18.8000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-01-25 14:46:21', '2018-01-25 14:46:21'),
(141, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Wed, 20 Jun 18', 'now', '', '', '26.8000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-06-20 18:17:37', '2018-06-20 18:17:37'),
(142, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Wed, 20 Jun 18', 'now', '', '', '18.8000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-06-20 18:19:02', '2018-06-20 18:19:02'),
(143, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Wed, 20 Jun 18', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-06-20 18:30:11', '2018-06-20 18:30:11'),
(144, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Wed, 20 Jun 18', 'now', '', '', '15.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-06-20 19:08:47', '2018-06-20 19:08:47'),
(145, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Wed, 20 Jun 18', 'now', '', '', '10.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1; rv:52.0) Gecko/20100101 Firefox/52.0', 'en-US,en;q=0.5', '2018-06-20 19:19:49', '2018-06-20 19:19:49'),
(146, 0, 'INV-2013-00', 4, 'Monkey King Thai Restaurant', 'http://192.168.1.220/', 0, 1, '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', 'cod', '', '', 'tableorder@order2.com', '', '', '', '', '', '', '', 0, '', 0, '', 0, '', '', 'DineIn', '00:30', 'Wed, 20 Jun 18', 'now', '', '', '15.0000', 1, 0, '0.0000', 0, '', 1, 4, 'AUD', '1.00000000', '192.168.1.220', '', 'Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.112 Safari/537.36', 'en-GB,en-US;q=0.8,en;q=0.6', '2018-06-20 19:34:55', '2018-06-20 19:34:55');

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_coupon`
--

CREATE TABLE `oc_order_coupon` (
  `order_coupon_id` int(11) UNSIGNED NOT NULL,
  `order_id` int(11) NOT NULL,
  `type` tinyint(1) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `name` varchar(255) NOT NULL,
  `info` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_order_coupon`
--

INSERT INTO `oc_order_coupon` (`order_coupon_id`, `order_id`, `type`, `amount`, `name`, `info`) VALUES
(1, 1, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.85  this order; $3.85 total; 8 orders to go'),
(2, 2, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.99  this order; $0.99 total; 8 orders to go'),
(3, 3, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.23  this order; $3.23 total; 8 orders to go'),
(4, 4, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(5, 5, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(6, 6, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(7, 7, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(8, 8, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.24  this order; $1.24 total; 8 orders to go'),
(9, 9, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(10, 10, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.23  this order; $3.23 total; 8 orders to go'),
(11, 11, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $5.46  this order; $5.46 total; 8 orders to go'),
(12, 12, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(13, 13, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(14, 14, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(15, 15, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(16, 16, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.24  this order; $1.24 total; 8 orders to go'),
(17, 17, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.73  this order; $3.73 total; 8 orders to go'),
(18, 18, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.48  this order; $3.48 total; 8 orders to go'),
(19, 19, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.86  this order; $1.86 total; 8 orders to go'),
(20, 20, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.74  this order; $0.74 total; 8 orders to go'),
(21, 21, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(22, 22, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.75  this order; $3.75 total; 8 orders to go'),
(23, 23, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.63  this order; $2.63 total; 8 orders to go'),
(24, 24, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(25, 25, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.25  this order; $3.25 total; 8 orders to go'),
(26, 26, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $13.66  this order; $13.66 total; 8 orders to go'),
(27, 27, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.63  this order; $1.63 total; 8 orders to go'),
(28, 28, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(29, 29, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(30, 30, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(31, 31, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.38  this order; $1.38 total; 8 orders to go'),
(32, 32, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(33, 33, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(34, 34, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.75  this order; $3.75 total; 8 orders to go'),
(35, 35, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(36, 36, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(37, 37, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(38, 38, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(39, 39, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(40, 40, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.61  this order; $2.61 total; 8 orders to go'),
(41, 41, 1, '0.00', '10% OFF YOUR 1ST ORDER', ''),
(42, 42, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(43, 43, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(44, 44, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(45, 45, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(46, 46, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.48  this order; $2.48 total; 8 orders to go'),
(47, 47, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.38  this order; $1.38 total; 8 orders to go'),
(48, 48, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.59  this order; $3.59 total; 8 orders to go'),
(49, 49, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $4.59  this order; $4.59 total; 8 orders to go'),
(50, 50, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(51, 51, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(52, 52, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.61  this order; $2.61 total; 8 orders to go'),
(53, 53, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.61  this order; $3.61 total; 8 orders to go'),
(54, 54, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(55, 55, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.88  this order; $1.88 total; 8 orders to go'),
(56, 56, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(57, 57, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.11  this order; $1.11 total; 8 orders to go'),
(58, 58, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(59, 59, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.11  this order; $1.11 total; 8 orders to go'),
(60, 60, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(61, 61, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(62, 62, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.36  this order; $2.36 total; 8 orders to go'),
(63, 63, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(64, 64, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.36  this order; $1.36 total; 8 orders to go'),
(65, 65, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(66, 66, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(67, 67, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(68, 68, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.86  this order; $2.86 total; 8 orders to go'),
(69, 69, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(70, 70, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $4.98  this order; $4.98 total; 8 orders to go'),
(71, 71, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(72, 72, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(73, 73, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(74, 74, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(75, 75, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(76, 76, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $5.23  this order; $5.23 total; 8 orders to go'),
(77, 77, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(78, 78, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(79, 79, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(80, 80, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(81, 81, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(82, 82, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.11  this order; $1.11 total; 8 orders to go'),
(83, 83, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(84, 84, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(85, 85, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(86, 86, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(87, 87, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(88, 88, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(89, 89, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.61  this order; $1.61 total; 8 orders to go'),
(90, 90, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(91, 91, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.11  this order; $1.11 total; 8 orders to go'),
(92, 92, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(93, 93, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(94, 94, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.11  this order; $1.11 total; 8 orders to go'),
(95, 95, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(96, 96, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.86  this order; $2.86 total; 8 orders to go'),
(97, 97, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(98, 98, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(99, 99, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(100, 100, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.86  this order; $2.86 total; 8 orders to go'),
(101, 101, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.86  this order; $2.86 total; 8 orders to go'),
(102, 102, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.61  this order; $2.61 total; 8 orders to go'),
(103, 103, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.86  this order; $2.86 total; 8 orders to go'),
(104, 104, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.24  this order; $2.24 total; 8 orders to go'),
(105, 105, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.86  this order; $1.86 total; 8 orders to go'),
(106, 106, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.88  this order; $1.88 total; 8 orders to go'),
(107, 107, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.49  this order; $2.49 total; 8 orders to go'),
(108, 108, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(109, 109, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(110, 110, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(111, 111, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(112, 112, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.36  this order; $2.36 total; 8 orders to go'),
(113, 113, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(114, 114, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.38  this order; $1.38 total; 8 orders to go'),
(115, 115, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(116, 116, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.11  this order; $3.11 total; 8 orders to go'),
(117, 117, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.74  this order; $0.74 total; 8 orders to go'),
(118, 118, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.74  this order; $0.74 total; 8 orders to go'),
(119, 119, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.11  this order; $3.11 total; 8 orders to go'),
(120, 120, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.11  this order; $3.11 total; 8 orders to go'),
(121, 121, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.11  this order; $3.11 total; 8 orders to go'),
(122, 122, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.11  this order; $1.11 total; 8 orders to go'),
(123, 123, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.61  this order; $2.61 total; 8 orders to go'),
(124, 124, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(125, 125, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.11  this order; $2.11 total; 8 orders to go'),
(126, 126, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.63  this order; $0.63 total; 8 orders to go'),
(127, 127, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.36  this order; $2.36 total; 8 orders to go'),
(128, 128, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.00  this order; $0.00 total; 8 orders to go'),
(129, 129, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.36  this order; $2.36 total; 8 orders to go'),
(130, 130, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.63  this order; $0.63 total; 8 orders to go'),
(131, 131, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.74  this order; $0.74 total; 8 orders to go'),
(132, 132, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.63  this order; $0.63 total; 8 orders to go'),
(133, 133, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.24  this order; $1.24 total; 8 orders to go'),
(134, 134, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.23  this order; $2.23 total; 8 orders to go'),
(135, 135, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.63  this order; $0.63 total; 8 orders to go'),
(136, 136, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.36  this order; $3.36 total; 8 orders to go'),
(137, 137, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.11  this order; $1.11 total; 8 orders to go'),
(138, 138, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.60  this order; $0.60 total; 8 orders to go'),
(139, 139, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.36  this order; $1.36 total; 8 orders to go'),
(140, 140, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.35  this order; $2.35 total; 8 orders to go'),
(141, 141, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $3.35  this order; $3.35 total; 8 orders to go'),
(142, 142, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $2.35  this order; $2.35 total; 8 orders to go'),
(143, 143, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.38  this order; $0.38 total; 8 orders to go'),
(144, 144, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.88  this order; $1.88 total; 8 orders to go'),
(145, 145, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $0.60  this order; $0.60 total; 8 orders to go'),
(146, 146, 3, '0.00', 'ORDER 8 TIMES 9TH IS FREE', 'loyalty credit $1.88  this order; $1.88 total; 8 orders to go');

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_custom_field`
--

CREATE TABLE `oc_order_custom_field` (
  `order_custom_field_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `custom_field_id` int(11) NOT NULL,
  `custom_field_value_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `value` text NOT NULL,
  `type` varchar(32) NOT NULL,
  `location` varchar(16) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_ext`
--

CREATE TABLE `oc_order_ext` (
  `order_ext_id` int(11) UNSIGNED NOT NULL,
  `product_ext_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `order_product_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_order_ext`
--

INSERT INTO `oc_order_ext` (`order_ext_id`, `product_ext_id`, `product_id`, `order_product_id`) VALUES
(1, 300301, 300, 1),
(2, 38030, 38, 2),
(3, 37030, 37, 3),
(4, 37206, 37, 3),
(5, 132308, 132, 4),
(6, 132312, 132, 4),
(7, 1205, 1, 5),
(8, 139324, 139, 9),
(9, 139312, 139, 11),
(10, 297299, 297, 20),
(11, 45033, 45, 22),
(12, 45031, 45, 23),
(13, 27033, 27, 24),
(14, 139324, 139, 31),
(15, 3206, 3, 34),
(16, 3205, 3, 35),
(17, 57064, 57, 36),
(18, 3205, 3, 46),
(19, 17206, 17, 57),
(20, 17205, 17, 58),
(21, 20206, 20, 59),
(22, 132308, 132, 60),
(23, 132314, 132, 60),
(24, 132308, 132, 61),
(25, 132308, 132, 62),
(26, 9205, 9, 63),
(27, 12206, 12, 64),
(28, 3205, 3, 68),
(29, 6206, 6, 71),
(30, 22205, 22, 74),
(31, 17206, 17, 76),
(32, 20206, 20, 77),
(33, 17205, 17, 89),
(34, 16206, 16, 92),
(35, 4205, 4, 105),
(36, 60063, 60, 107),
(37, 41206, 41, 109),
(38, 17205, 17, 127),
(39, 45033, 45, 128),
(40, 55065, 55, 146),
(41, 55206, 55, 146),
(42, 39206, 39, 147),
(43, 39317, 39, 147),
(44, 41206, 41, 148),
(45, 41317, 41, 148),
(46, 37316, 37, 150),
(47, 37316, 37, 152),
(48, 37034, 37, 153),
(49, 69205, 69, 154),
(50, 3205, 3, 158),
(51, 4205, 4, 159),
(52, 69205, 69, 160),
(53, 17206, 17, 167),
(54, 5206, 5, 168),
(55, 6206, 6, 169),
(56, 68206, 68, 171);

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_history`
--

CREATE TABLE `oc_order_history` (
  `order_history_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `order_status_id` int(11) NOT NULL,
  `notify` tinyint(1) NOT NULL DEFAULT '0',
  `comment` text NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_order_history`
--

INSERT INTO `oc_order_history` (`order_history_id`, `order_id`, `order_status_id`, `notify`, `comment`, `date_added`) VALUES
(1, 1, 1, 0, '', '2017-08-01 17:18:48'),
(2, 2, 1, 0, '', '2017-08-01 17:23:34'),
(3, 3, 1, 0, '', '2017-08-01 17:35:14'),
(4, 4, 1, 0, '', '2017-08-02 11:07:52'),
(5, 5, 1, 0, '', '2017-08-02 15:26:14'),
(6, 6, 1, 0, '', '2017-08-02 15:33:00'),
(7, 7, 1, 0, '', '2017-08-02 15:39:38'),
(8, 8, 1, 0, '', '2017-08-04 11:38:40'),
(9, 11, 1, 0, '', '2017-08-04 12:02:48'),
(10, 12, 1, 0, '', '2017-08-04 12:14:57'),
(11, 13, 1, 0, '', '2017-08-09 12:26:37'),
(12, 14, 1, 0, '', '2017-08-09 12:32:38'),
(13, 15, 1, 0, '', '2017-08-09 12:34:15'),
(14, 16, 1, 0, '', '2017-08-10 11:52:12'),
(15, 17, 1, 0, '', '2017-08-16 17:50:48'),
(16, 18, 1, 0, '', '2017-08-16 17:58:02'),
(17, 19, 1, 0, '', '2017-08-16 18:23:56'),
(18, 20, 1, 0, '', '2017-08-17 10:35:37'),
(19, 21, 1, 0, '', '2017-08-17 10:41:40'),
(20, 22, 1, 0, '', '2017-08-22 13:18:58'),
(21, 23, 1, 0, '', '2017-08-22 13:20:35'),
(22, 24, 1, 0, '', '2017-08-22 14:00:26'),
(23, 25, 1, 0, '', '2017-08-25 16:50:44'),
(24, 26, 1, 0, '', '2017-08-25 16:57:07'),
(25, 27, 1, 0, '', '2017-08-25 16:59:16'),
(26, 28, 1, 0, '', '2017-08-25 17:43:04'),
(27, 29, 1, 0, '', '2017-08-25 18:01:16'),
(28, 30, 1, 0, '', '2017-08-28 15:56:11'),
(29, 31, 1, 0, '', '2017-08-28 16:08:49'),
(30, 32, 1, 0, '', '2017-08-29 17:13:55'),
(31, 33, 1, 0, '', '2017-08-29 17:49:54'),
(32, 34, 1, 0, '', '2017-08-29 17:52:08'),
(33, 35, 1, 0, '', '2017-09-07 16:36:19'),
(34, 36, 1, 0, '', '2017-09-07 17:02:35'),
(35, 37, 1, 0, '', '2017-09-07 17:06:53'),
(36, 38, 1, 0, '', '2017-09-07 17:11:07'),
(37, 39, 1, 0, '', '2017-09-07 17:11:54'),
(38, 40, 1, 0, '', '2017-09-07 17:19:02'),
(39, 41, 1, 0, '', '2017-09-07 17:58:27'),
(40, 42, 1, 0, '', '2017-09-07 18:04:43'),
(41, 43, 1, 0, '', '2017-09-07 18:13:37'),
(42, 44, 1, 0, '', '2017-09-07 18:23:54'),
(43, 45, 1, 0, '', '2017-09-07 18:29:41'),
(44, 46, 1, 0, '', '2017-09-07 18:34:45'),
(45, 47, 1, 0, '', '2017-09-07 18:41:21'),
(46, 48, 1, 0, '', '2017-09-07 18:43:08'),
(47, 49, 1, 0, '', '2017-09-07 18:45:13'),
(48, 50, 1, 0, '', '2017-09-07 18:51:54'),
(49, 51, 1, 0, '', '2017-09-07 18:53:38'),
(50, 52, 1, 0, '', '2017-09-07 18:55:53'),
(51, 53, 1, 0, '', '2017-09-08 10:41:12'),
(52, 54, 1, 0, '', '2017-09-08 10:50:20'),
(53, 55, 1, 0, '', '2017-09-08 10:53:57'),
(54, 56, 1, 0, '', '2017-09-13 15:29:06'),
(55, 57, 1, 0, '', '2017-09-13 16:11:16'),
(56, 58, 1, 0, '', '2017-09-13 16:16:42'),
(57, 59, 1, 0, '', '2017-09-13 16:18:58'),
(58, 60, 1, 0, '', '2017-09-13 16:23:12'),
(59, 61, 1, 0, '', '2017-09-13 16:24:54'),
(60, 62, 1, 0, '', '2017-09-13 16:25:34'),
(61, 63, 1, 0, '', '2017-09-13 16:58:51'),
(62, 64, 1, 0, '', '2017-09-14 13:55:37'),
(63, 65, 1, 0, '', '2017-09-20 11:07:17'),
(64, 66, 1, 0, '', '2017-09-20 11:15:15'),
(65, 67, 1, 0, '', '2017-09-28 14:38:14'),
(66, 68, 1, 0, '', '2017-09-29 18:41:08'),
(67, 69, 1, 0, '', '2017-09-29 18:54:59'),
(68, 70, 1, 0, '', '2017-09-29 19:00:45'),
(69, 71, 1, 0, '', '2017-09-29 19:04:54'),
(70, 73, 1, 0, '', '2017-09-29 19:11:39'),
(71, 74, 1, 0, '', '2017-09-29 19:17:28'),
(72, 75, 1, 0, '', '2017-09-29 19:20:23'),
(73, 76, 1, 0, '', '2017-09-29 19:28:43'),
(74, 77, 1, 0, '', '2017-09-29 19:32:39'),
(75, 78, 1, 0, '', '2017-09-29 19:35:49'),
(76, 79, 1, 0, '', '2017-09-29 19:51:39'),
(77, 80, 1, 0, '', '2017-09-29 19:58:04'),
(78, 81, 1, 0, '', '2017-09-29 20:00:19'),
(79, 82, 1, 0, '', '2017-09-29 20:02:21'),
(80, 83, 1, 0, '', '2017-09-29 20:06:19'),
(81, 84, 1, 0, '', '2017-09-29 20:07:35'),
(82, 85, 1, 0, '', '2017-10-03 10:01:56'),
(83, 86, 1, 0, '', '2017-10-03 10:05:34'),
(84, 87, 1, 0, '', '2017-10-03 10:08:24'),
(85, 88, 1, 0, '', '2017-10-03 10:17:50'),
(86, 89, 1, 0, '', '2017-10-03 10:19:12'),
(87, 90, 1, 0, '', '2017-10-03 10:22:53'),
(88, 91, 1, 0, '', '2017-10-03 10:31:27'),
(89, 92, 1, 0, '', '2017-10-20 11:43:01'),
(90, 93, 1, 0, '', '2017-10-23 12:50:41'),
(91, 94, 1, 0, '', '2017-10-23 12:52:29'),
(92, 95, 1, 0, '', '2017-10-23 12:54:11'),
(93, 96, 1, 0, '', '2017-10-23 12:55:58'),
(94, 97, 1, 0, '', '2017-10-24 11:11:31'),
(95, 98, 1, 0, '', '2017-10-24 12:24:14'),
(96, 99, 1, 0, '', '2017-11-17 12:03:56'),
(97, 101, 1, 0, '', '2017-11-17 12:10:17'),
(98, 102, 1, 0, '', '2017-11-17 12:12:46'),
(99, 103, 1, 0, '', '2017-11-17 12:19:55'),
(100, 104, 1, 0, '', '2017-11-17 18:39:33'),
(101, 105, 1, 0, '', '2017-11-17 18:42:50'),
(102, 106, 1, 0, '', '2018-01-10 12:09:34'),
(103, 107, 1, 0, '', '2018-01-12 12:38:15'),
(104, 108, 1, 0, '', '2018-01-12 12:40:12'),
(105, 109, 1, 0, '', '2018-01-17 14:13:27'),
(106, 110, 1, 0, '', '2018-01-17 14:21:10'),
(107, 111, 1, 0, '', '2018-01-17 14:22:27'),
(108, 112, 1, 0, '', '2018-01-19 15:51:33'),
(109, 113, 1, 0, '', '2018-01-19 15:58:11'),
(110, 114, 1, 0, '', '2018-01-19 16:00:03'),
(111, 115, 1, 0, '', '2018-01-19 16:02:07'),
(112, 116, 1, 0, '', '2018-01-19 16:13:28'),
(113, 117, 1, 0, '', '2018-01-19 16:19:07'),
(114, 118, 1, 0, '', '2018-01-19 16:23:46'),
(115, 121, 1, 0, '', '2018-01-19 16:30:36'),
(116, 122, 1, 0, '', '2018-01-22 12:50:22'),
(117, 123, 1, 0, '', '2018-01-22 12:51:20'),
(118, 124, 1, 0, '', '2018-01-22 12:52:41'),
(119, 125, 1, 0, '', '2018-01-22 12:58:46'),
(120, 126, 1, 0, '', '2018-01-22 13:47:33'),
(121, 127, 1, 0, '', '2018-01-22 15:12:19'),
(122, 128, 1, 0, '', '2018-01-22 15:12:42'),
(123, 129, 1, 0, '', '2018-01-22 15:13:24'),
(124, 130, 1, 0, '', '2018-01-22 15:14:44'),
(125, 131, 1, 0, '', '2018-01-22 15:18:15'),
(126, 132, 1, 0, '', '2018-01-22 15:31:30'),
(127, 133, 1, 0, '', '2018-01-24 20:04:04'),
(128, 134, 1, 0, '', '2018-01-24 20:07:00'),
(129, 135, 1, 0, '', '2018-01-25 12:22:06'),
(130, 136, 1, 0, '', '2018-01-25 13:04:25'),
(131, 137, 1, 0, '', '2018-01-25 13:23:02'),
(132, 138, 1, 0, '', '2018-01-25 13:24:38'),
(133, 139, 1, 0, '', '2018-01-25 14:22:20'),
(134, 140, 1, 0, '', '2018-01-25 14:46:21'),
(135, 141, 1, 0, '', '2018-06-20 18:17:37'),
(136, 142, 1, 0, '', '2018-06-20 18:19:02'),
(137, 143, 1, 0, '', '2018-06-20 18:30:11'),
(138, 144, 1, 0, '', '2018-06-20 19:08:47'),
(139, 145, 1, 0, '', '2018-06-20 19:19:49'),
(140, 146, 1, 0, '', '2018-06-20 19:34:55');

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_option`
--

CREATE TABLE `oc_order_option` (
  `order_option_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `order_product_id` int(11) NOT NULL,
  `product_option_id` int(11) NOT NULL,
  `product_option_value_id` int(11) NOT NULL DEFAULT '0',
  `name` varchar(255) NOT NULL,
  `value` text NOT NULL,
  `type` varchar(32) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_order_option`
--

INSERT INTO `oc_order_option` (`order_option_id`, `order_id`, `order_product_id`, `product_option_id`, `product_option_value_id`, `name`, `value`, `type`) VALUES
(1, 23, 29, 1, 2, 'sweet', 't', 'radio'),
(2, 23, 30, 1, 1, 'sweet', 'm', 'radio'),
(3, 25, 32, 5, 11, 'sweet2', 'sw2', 'radio'),
(4, 25, 33, 5, 10, 'sweet2', 'sw1', 'radio'),
(5, 27, 39, 5, 10, 'sweet2', 'sw1', 'radio'),
(6, 27, 40, 2, 4, 'S2', 'Medium', 'radio'),
(7, 27, 41, 2, 3, 'S2', 'Small', 'radio'),
(8, 28, 43, 6, 13, 'S1', 'Big', 'radio'),
(9, 29, 44, 6, 13, 'S1', 'Big1', 'radio'),
(10, 30, 45, 8, 23, 'Size', 'ExtraSmall', 'radio'),
(11, 31, 47, 8, 23, 'Size', 'ExtraSmall', 'radio'),
(12, 32, 48, 7, 28, 'Size', 'Small8', 'radio'),
(13, 33, 49, 7, 28, 'Size', 'Small8', 'radio'),
(14, 34, 50, 8, 25, 'Size', 'Big3', 'radio'),
(15, 47, 65, 8, 23, 'Size', 'ExtraSmall', 'radio'),
(16, 48, 66, 8, 25, 'Size', 'Big3', 'radio'),
(17, 48, 67, 9, 29, 'Size', 'Big3', 'radio'),
(18, 49, 69, 8, 23, 'Size', 'ExtraSmall', 'radio'),
(19, 49, 70, 9, 29, 'Size', 'Big3', 'radio'),
(20, 53, 75, 8, 23, 'Size', 'ExtraSmall', 'radio'),
(21, 55, 78, 8, 25, 'Size', 'Big3', 'radio'),
(22, 106, 129, 8, 25, 'Size', 'Big3', 'radio'),
(23, 114, 137, 8, 23, 'Size', 'ExtraSmall', 'radio'),
(24, 138, 163, 9, 29, 'Size', 'Big3', 'radio'),
(25, 144, 172, 8, 25, 'Size', 'Big3', 'radio'),
(26, 145, 173, 9, 29, 'Size', 'Big3', 'radio'),
(27, 146, 174, 8, 25, 'Size', 'Big3', 'radio');

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_product`
--

CREATE TABLE `oc_order_product` (
  `order_product_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `model` varchar(64) NOT NULL,
  `quantity` int(4) NOT NULL,
  `price` decimal(15,4) NOT NULL DEFAULT '0.0000',
  `total` decimal(15,4) NOT NULL DEFAULT '0.0000',
  `tax` decimal(15,4) NOT NULL DEFAULT '0.0000',
  `reward` int(8) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_order_product`
--

INSERT INTO `oc_order_product` (`order_product_id`, `order_id`, `product_id`, `name`, `model`, `quantity`, `price`, `total`, `tax`, `reward`) VALUES
(1, 1, 300, 'Soft Drinks - Can', '1', 1, '3.0000', '3.0000', '0.0000', 0),
(2, 1, 38, 'Red Curry (GF)', '1', 1, '0.0000', '13.9000', '0.0000', 0),
(3, 1, 37, 'Green Curry (GF)', '1', 1, '0.0000', '13.9000', '0.0000', 0),
(4, 1, 132, 'Happy Set', '1', 1, '62.9000', '62.9000', '0.0000', 0),
(5, 2, 1, 'Spring Roll (4 Pcs)', '1', 1, '7.9000', '7.9000', '0.0000', 0),
(6, 3, 1, 'Spring Roll (4 Pcs)', '1', 1, '7.9000', '7.9000', '0.0000', 0),
(7, 3, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(8, 4, 41, 'Yellow Chicken Curry (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(9, 5, 139, 'Couple Set', '1', 1, '39.9000', '39.9000', '0.0000', 0),
(10, 6, 20, 'Papaya Salad with Grilled Chicken', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(11, 7, 139, 'Couple Set', '1', 1, '39.9000', '39.9000', '0.0000', 0),
(12, 8, 12, 'Tom Yum Prawn', '1', 1, '9.9000', '9.9000', '0.0000', 0),
(13, 9, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(14, 10, 16, 'Papaya Salad (Somtum)', '1', 2, '12.9000', '25.8000', '0.0000', 0),
(15, 11, 16, 'Papaya Salad (Somtum)', '1', 2, '12.9000', '25.8000', '0.0000', 0),
(16, 11, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(17, 12, 41, 'Yellow Chicken Curry (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(18, 13, 20, 'Papaya Salad with Grilled Chicken', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(19, 14, 54, 'King Prawns with Lime Leaves & Peppercorns (4 Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(20, 15, 297, 'Marinated (Chicken or Beef)', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(21, 16, 12, 'Tom Yum Prawn', '1', 1, '9.9000', '9.9000', '0.0000', 0),
(22, 17, 45, 'Pad Kee Mao', '1', 2, '0.0000', '29.8000', '0.0000', 0),
(23, 18, 45, 'Pad Kee Mao', '1', 2, '0.0000', '27.8000', '0.0000', 0),
(24, 19, 27, 'Peanut Sauce', '1', 1, '0.0000', '14.9000', '0.0000', 0),
(25, 20, 71, 'Prawn Cracker with Chilli Jam', '1', 1, '5.9000', '5.9000', '0.0000', 0),
(26, 21, 20, 'Papaya Salad with Grilled Chicken', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(27, 22, 323, 'test1', '', 1, '10.0000', '10.0000', '0.0000', 0),
(28, 22, 323, 'test1', '', 2, '10.0000', '20.0000', '0.0000', 0),
(29, 23, 323, 'test1', '', 1, '10.0000', '10.0000', '0.0000', 0),
(30, 23, 323, 'test1', '', 1, '11.0000', '11.0000', '0.0000', 0),
(31, 24, 139, 'Couple Set', '1', 1, '39.9000', '39.9000', '0.0000', 0),
(32, 25, 325, 'test5', '', 5, '2.0000', '10.0000', '0.0000', 0),
(33, 25, 325, 'test5', '', 8, '2.0000', '16.0000', '0.0000', 0),
(34, 26, 3, 'Satay Chicken (6 Pcs)', '1', 2, '8.9000', '17.8000', '0.0000', 0),
(35, 26, 3, 'Satay Chicken (6 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(36, 26, 57, 'Salmon Green Curry', '1', 1, '22.9000', '22.9000', '0.0000', 0),
(37, 26, 50, 'Royal Duck Curry', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(38, 26, 20, 'Papaya Salad with Grilled Chicken', '1', 2, '19.9000', '39.8000', '0.0000', 0),
(39, 27, 325, 'test5', '', 1, '2.0000', '2.0000', '0.0000', 0),
(40, 27, 1, '3Lamb SatayTest1a', '', 1, '6.0000', '6.0000', '0.0000', 0),
(41, 27, 1, '3Lamb SatayTest1a', '', 1, '5.0000', '5.0000', '0.0000', 0),
(42, 28, 1, '3Lamb SatayTest1a', '', 1, '3.5000', '3.5000', '0.0000', 0),
(43, 28, 1, '3Lamb SatayTest1a', '', 1, '3.5000', '3.5000', '0.0000', 0),
(44, 29, 1, '3Lamb SatayTest1a', '', 1, '3.5000', '3.5000', '0.0000', 0),
(45, 30, 325, 'test6a', '', 1, '11.0000', '11.0000', '0.0000', 0),
(46, 30, 3, 'Satay Chicken (6 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(47, 31, 325, 'test6a', '', 1, '11.0000', '11.0000', '0.0000', 0),
(48, 32, 1, '3Lamb', '', 1, '5.9000', '5.9000', '0.0000', 0),
(49, 33, 1, '3Lamb', '', 3, '5.9000', '17.7000', '0.0000', 0),
(50, 34, 325, 'test6a', '', 2, '15.0000', '30.0000', '0.0000', 0),
(51, 35, 50, 'Royal Duck Curry', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(52, 36, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(53, 37, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(54, 38, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(55, 39, 20, 'Papaya Salad with Grilled Chicken', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(56, 40, 22, 'Roasted Duck Salad', '1', 1, '20.9000', '20.9000', '0.0000', 0),
(57, 41, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(58, 41, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(59, 42, 20, 'Papaya Salad with Grilled Chicken', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(60, 43, 132, 'Happy Set', '1', 1, '62.9000', '62.9000', '0.0000', 0),
(61, 44, 132, 'Happy Set', '1', 1, '62.9000', '62.9000', '0.0000', 0),
(62, 45, 132, 'Happy Set', '1', 1, '62.9000', '62.9000', '0.0000', 0),
(63, 46, 9, 'Tom Kha Chicken', '1', 1, '9.9000', '9.9000', '0.0000', 0),
(64, 46, 12, 'Tom Yum Prawn', '1', 1, '9.9000', '9.9000', '0.0000', 0),
(65, 47, 325, 'test6a', '', 1, '11.0000', '11.0000', '0.0000', 0),
(66, 48, 325, 'test6a', '', 1, '15.0000', '15.0000', '0.0000', 0),
(67, 48, 326, 'test7', '1', 1, '4.8000', '4.8000', '0.0000', 0),
(68, 48, 3, 'Satay Chicken (6 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(69, 49, 325, 'test6a', '', 2, '11.0000', '22.0000', '0.0000', 0),
(70, 49, 326, 'test7', '1', 1, '4.8000', '4.8000', '0.0000', 0),
(71, 49, 6, 'Mix Entree (4 Pcs)', '1', 1, '9.9000', '9.9000', '0.0000', 0),
(72, 50, 20, 'Papaya Salad with Grilled Chicken', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(73, 51, 20, 'Papaya Salad with Grilled Chicken', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(74, 52, 22, 'Roasted Duck Salad', '1', 1, '20.9000', '20.9000', '0.0000', 0),
(75, 53, 325, 'test6a', '', 1, '11.0000', '11.0000', '0.0000', 0),
(76, 53, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(77, 54, 20, 'Papaya Salad with Grilled Chicken', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(78, 55, 325, 'test6a', '', 1, '15.0000', '15.0000', '0.0000', 0),
(79, 56, 41, 'Yellow Chicken Curry (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(80, 57, 3, 'Satay Chicken (6 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(81, 58, 41, 'Yellow Chicken Curry (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(82, 59, 3, 'Satay Chicken (6 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(83, 60, 19, 'Crispy Soft Shell Crab Salad', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(84, 61, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(85, 62, 48, 'Koo Wa Gai Noodle', '1', 1, '18.9000', '18.9000', '0.0000', 0),
(86, 63, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(87, 64, 7, 'Crispy Soft Shell Crab', '1', 1, '10.9000', '10.9000', '0.0000', 0),
(88, 65, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(89, 66, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(90, 67, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(91, 68, 13, 'Garlic & Pepper Lamb Cutlets', '1', 1, '22.9000', '22.9000', '0.0000', 0),
(92, 69, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(93, 70, 50, 'Royal Duck Curry', '1', 2, '19.9000', '39.8000', '0.0000', 0),
(94, 71, 39, 'Massaman Beef (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(95, 72, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(96, 73, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(97, 74, 54, 'King Prawns with Lime Leaves & Peppercorns (4 Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(98, 75, 297, 'Marinated (Chicken or Beef)', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(99, 76, 22, 'Roasted Duck Salad', '1', 2, '20.9000', '41.8000', '0.0000', 0),
(100, 77, 54, 'King Prawns with Lime Leaves & Peppercorns (4 Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(101, 78, 54, 'King Prawns with Lime Leaves & Peppercorns (4 Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(102, 79, 297, 'Marinated (Chicken or Beef)', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(103, 80, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(104, 81, 60, 'King Prawn Panang Curry (4Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(105, 82, 4, 'Steamed Dumplings (4 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(106, 83, 297, 'Marinated (Chicken or Beef)', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(107, 84, 60, 'King Prawn Panang Curry (4Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(108, 85, 39, 'Massaman Beef (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(109, 86, 41, 'Yellow Chicken Curry (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(110, 87, 54, 'King Prawns with Lime Leaves & Peppercorns (4 Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(111, 88, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(112, 89, 16, 'Papaya Salad (Somtum)', '1', 1, '12.9000', '12.9000', '0.0000', 0),
(113, 90, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(114, 91, 4, 'Steamed Dumplings (4 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(115, 92, 39, 'Massaman Beef (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(116, 93, 39, 'Massaman Beef (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(117, 94, 4, 'Steamed Dumplings (4 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(118, 95, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(119, 96, 13, 'Garlic & Pepper Lamb Cutlets', '1', 1, '22.9000', '22.9000', '0.0000', 0),
(120, 97, 39, 'Massaman Beef (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(121, 98, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(122, 99, 41, 'Yellow Chicken Curry (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(123, 100, 13, 'Garlic & Pepper Lamb Cutlets', '1', 1, '22.9000', '22.9000', '0.0000', 0),
(124, 101, 13, 'Garlic & Pepper Lamb Cutlets', '1', 1, '22.9000', '22.9000', '0.0000', 0),
(125, 102, 22, 'Roasted Duck Salad', '1', 1, '20.9000', '20.9000', '0.0000', 0),
(126, 103, 13, 'Garlic & Pepper Lamb Cutlets', '1', 1, '22.9000', '22.9000', '0.0000', 0),
(127, 104, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(128, 105, 45, 'Pad Kee Mao', '1', 1, '0.0000', '14.9000', '0.0000', 0),
(129, 106, 325, 'test6a', '', 1, '15.0000', '15.0000', '0.0000', 0),
(130, 107, 20, 'Papaya Salad with Grilled Chicken', '1', 1, '19.9000', '19.9000', '0.0000', 0),
(131, 108, 54, 'King Prawns with Lime Leaves & Peppercorns (4 Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(132, 109, 139, 'Couple Set', '1', 1, '39.9000', '39.9000', '0.0000', 0),
(133, 110, 139, 'Couple Set', '1', 1, '39.9000', '39.9000', '0.0000', 0),
(134, 111, 139, 'Couple Set', '1', 1, '39.9000', '39.9000', '0.0000', 0),
(135, 112, 48, 'Koo Wa Gai Noodle', '1', 1, '18.9000', '18.9000', '0.0000', 0),
(136, 113, 54, 'King Prawns with Lime Leaves & Peppercorns (4 Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(137, 114, 325, 'test6a', '', 1, '11.0000', '11.0000', '0.0000', 0),
(138, 115, 54, 'King Prawns with Lime Leaves & Peppercorns (4 Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(139, 116, 59, 'Duck Delight', '1', 1, '24.9000', '24.9000', '0.0000', 0),
(140, 117, 71, 'Prawn Cracker with Chilli Jam', '1', 1, '5.9000', '5.9000', '0.0000', 0),
(141, 118, 71, 'Prawn Cracker with Chilli Jam', '1', 1, '5.9000', '5.9000', '0.0000', 0),
(142, 119, 59, 'Duck Delight', '1', 1, '24.9000', '24.9000', '0.0000', 0),
(143, 120, 59, 'Duck Delight', '1', 1, '24.9000', '24.9000', '0.0000', 0),
(144, 121, 59, 'Duck Delight', '1', 1, '24.9000', '24.9000', '0.0000', 0),
(145, 122, 3, 'Satay Chicken (6 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(146, 123, 55, 'Pad Thai Punim (Crispy Soft Shell Crab)', '1', 1, '20.9000', '20.9000', '0.0000', 0),
(147, 124, 39, 'Massaman Beef (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(148, 125, 41, 'Yellow Chicken Curry (GF)', '1', 1, '16.9000', '16.9000', '0.0000', 0),
(149, 126, 69, 'Steamed Rice with Peanut Sauce', '1', 1, '5.0000', '5.0000', '0.0000', 0),
(150, 127, 37, 'Green Curry (GF)', '1', 1, '0.0000', '0.0000', '0.0000', 0),
(151, 127, 48, 'Koo Wa Gai Noodle', '1', 1, '18.9000', '18.9000', '0.0000', 0),
(152, 128, 37, 'Green Curry (GF)', '1', 1, '0.0000', '0.0000', '0.0000', 0),
(153, 129, 37, 'Green Curry (GF)', '1', 1, '0.0000', '18.9000', '0.0000', 0),
(154, 130, 69, 'Steamed Rice with Peanut Sauce', '1', 1, '5.0000', '5.0000', '0.0000', 0),
(155, 131, 71, 'Prawn Cracker with Chilli Jam', '1', 1, '5.9000', '5.9000', '0.0000', 0),
(156, 132, 69, 'Steamed Rice with Peanut Sauce', '1', 1, '5.0000', '5.0000', '0.0000', 0),
(157, 133, 6, 'Mix Entree (4 Pcs)', '1', 1, '9.9000', '9.9000', '0.0000', 0),
(158, 134, 3, 'Satay Chicken (6 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(159, 134, 4, 'Steamed Dumplings (4 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(160, 135, 69, 'Steamed Rice with Peanut Sauce', '1', 1, '5.0000', '5.0000', '0.0000', 0),
(161, 136, 54, 'King Prawns with Lime Leaves & Peppercorns (4 Pcs)', '1', 1, '26.9000', '26.9000', '0.0000', 0),
(162, 137, 3, 'Satay Chicken (6 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(163, 138, 326, 'test7', '1', 1, '4.8000', '4.8000', '0.0000', 0),
(164, 139, 7, 'Crispy Soft Shell Crab', '1', 1, '10.9000', '10.9000', '0.0000', 0),
(165, 140, 5, 'Fish Cake (4 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(166, 140, 6, 'Mix Entree (4 Pcs)', '1', 1, '9.9000', '9.9000', '0.0000', 0),
(167, 141, 17, 'Nam Tok', '1', 1, '17.9000', '17.9000', '0.0000', 0),
(168, 141, 5, 'Fish Cake (4 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(169, 142, 6, 'Mix Entree (4 Pcs)', '1', 1, '9.9000', '9.9000', '0.0000', 0),
(170, 142, 5, 'Fish Cake (4 Pcs)', '1', 1, '8.9000', '8.9000', '0.0000', 0),
(171, 143, 68, 'Roti', '1', 1, '3.0000', '3.0000', '0.0000', 0),
(172, 144, 325, 'test6a', '', 1, '15.0000', '15.0000', '0.0000', 0),
(173, 145, 326, 'test7', '1', 1, '4.8000', '4.8000', '0.0000', 0),
(174, 146, 325, 'test6a', '', 1, '15.0000', '15.0000', '0.0000', 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_recurring`
--

CREATE TABLE `oc_order_recurring` (
  `order_recurring_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `reference` varchar(255) NOT NULL,
  `product_id` int(11) NOT NULL,
  `product_name` varchar(255) NOT NULL,
  `product_quantity` int(11) NOT NULL,
  `recurring_id` int(11) NOT NULL,
  `recurring_name` varchar(255) NOT NULL,
  `recurring_description` varchar(255) NOT NULL,
  `recurring_frequency` varchar(25) NOT NULL,
  `recurring_cycle` smallint(6) NOT NULL,
  `recurring_duration` smallint(6) NOT NULL,
  `recurring_price` decimal(10,4) NOT NULL,
  `trial` tinyint(1) NOT NULL,
  `trial_frequency` varchar(25) NOT NULL,
  `trial_cycle` smallint(6) NOT NULL,
  `trial_duration` smallint(6) NOT NULL,
  `trial_price` decimal(10,4) NOT NULL,
  `status` tinyint(4) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_recurring_transaction`
--

CREATE TABLE `oc_order_recurring_transaction` (
  `order_recurring_transaction_id` int(11) NOT NULL,
  `order_recurring_id` int(11) NOT NULL,
  `reference` varchar(255) NOT NULL,
  `type` varchar(255) NOT NULL,
  `amount` decimal(10,4) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_status`
--

CREATE TABLE `oc_order_status` (
  `order_status_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(32) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_order_status`
--

INSERT INTO `oc_order_status` (`order_status_id`, `language_id`, `name`) VALUES
(1, 1, 'Pending'),
(2, 1, 'Accepted'),
(3, 1, 'Finished'),
(4, 1, 'Cancelling'),
(5, 1, 'Refunded');

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_total`
--

CREATE TABLE `oc_order_total` (
  `order_total_id` int(10) NOT NULL,
  `order_id` int(11) NOT NULL,
  `code` varchar(32) NOT NULL,
  `title` varchar(255) NOT NULL,
  `value` decimal(15,4) NOT NULL DEFAULT '0.0000',
  `sort_order` int(3) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_order_total`
--

INSERT INTO `oc_order_total` (`order_total_id`, `order_id`, `code`, `title`, `value`, `sort_order`) VALUES
(1, 1, 'sub_total', 'Sub-Total', '93.7000', 1),
(2, 1, 'shipping', 'Pick-up', '0.0000', 3),
(3, 1, 'total', 'Total', '93.7000', 9),
(4, 2, 'sub_total', 'Sub-Total', '7.9000', 1),
(5, 2, 'shipping', 'Pick-up', '0.0000', 3),
(6, 2, 'low_order_fee', 'Additional charges', '2.1000', 8),
(7, 2, 'total', 'Total', '10.0000', 9),
(8, 3, 'sub_total', 'Sub-Total', '25.8000', 1),
(9, 3, 'shipping', 'Pick-up', '0.0000', 3),
(10, 3, 'total', 'Total', '25.8000', 9),
(11, 4, 'sub_total', 'Sub-Total', '16.9000', 1),
(12, 4, 'shipping', 'Delivery', '5.0000', 3),
(13, 4, 'total', 'Total', '21.9000', 9),
(14, 5, 'sub_total', 'Sub-Total', '39.9000', 1),
(15, 5, 'shipping', 'Pick-up', '0.0000', 3),
(16, 5, 'total', 'Total', '39.9000', 9),
(17, 6, 'sub_total', 'Sub-Total', '19.9000', 1),
(18, 6, 'shipping', 'Pick-up', '0.0000', 3),
(19, 6, 'total', 'Total', '19.9000', 9),
(20, 7, 'sub_total', 'Sub-Total', '39.9000', 1),
(21, 7, 'shipping', 'Pick-up', '0.0000', 3),
(22, 7, 'total', 'Total', '39.9000', 9),
(23, 8, 'sub_total', 'Sub-Total', '9.9000', 1),
(24, 8, 'shipping', 'Pick-up', '0.0000', 3),
(25, 8, 'low_order_fee', 'Additional charges', '0.1000', 8),
(26, 8, 'total', 'Total', '10.0000', 9),
(27, 9, 'sub_total', 'Sub-Total', '12.9000', 1),
(28, 9, 'shipping', 'Pick-up', '0.0000', 3),
(29, 9, 'total', 'Total', '12.9000', 9),
(30, 10, 'sub_total', 'Sub-Total', '25.8000', 1),
(31, 10, 'shipping', 'Pick-up', '0.0000', 3),
(32, 10, 'total', 'Total', '25.8000', 9),
(33, 11, 'sub_total', 'Sub-Total', '43.7000', 1),
(34, 11, 'shipping', 'Pick-up', '0.0000', 3),
(35, 11, 'total', 'Total', '43.7000', 9),
(36, 12, 'sub_total', 'Sub-Total', '16.9000', 1),
(37, 12, 'shipping', 'Pick-up', '0.0000', 3),
(38, 12, 'total', 'Total', '16.9000', 9),
(39, 13, 'sub_total', 'Sub-Total', '19.9000', 1),
(40, 13, 'shipping', 'Pick-up', '0.0000', 3),
(41, 13, 'total', 'Total', '19.9000', 9),
(42, 14, 'sub_total', 'Sub-Total', '26.9000', 1),
(43, 14, 'shipping', 'Pick-up', '0.0000', 3),
(44, 14, 'total', 'Total', '26.9000', 9),
(45, 15, 'sub_total', 'Sub-Total', '17.9000', 1),
(46, 15, 'shipping', 'Pick-up', '0.0000', 3),
(47, 15, 'total', 'Total', '17.9000', 9),
(48, 16, 'sub_total', 'Sub-Total', '9.9000', 1),
(49, 16, 'shipping', 'Pick-up', '0.0000', 3),
(50, 16, 'low_order_fee', 'Additional charges', '0.1000', 8),
(51, 16, 'total', 'Total', '10.0000', 9),
(52, 17, 'sub_total', 'Sub-Total', '29.8000', 1),
(53, 17, 'shipping', 'Pick-up', '0.0000', 3),
(54, 17, 'total', 'Total', '29.8000', 9),
(55, 18, 'sub_total', 'Sub-Total', '27.8000', 1),
(56, 18, 'shipping', 'Pick-up', '0.0000', 3),
(57, 18, 'total', 'Total', '27.8000', 9),
(58, 19, 'sub_total', 'Sub-Total', '14.9000', 1),
(59, 19, 'shipping', 'Delivery', '6.0000', 3),
(60, 19, 'total', 'Total', '20.9000', 9),
(61, 20, 'sub_total', 'Sub-Total', '5.9000', 1),
(62, 20, 'shipping', 'Pick-up', '0.0000', 3),
(63, 20, 'low_order_fee', 'Additional charges', '4.1000', 8),
(64, 20, 'total', 'Total', '10.0000', 9),
(65, 21, 'sub_total', 'Sub-Total', '19.9000', 1),
(66, 21, 'shipping', 'Delivery', '3.0000', 3),
(67, 21, 'total', 'Total', '22.9000', 9),
(68, 22, 'sub_total', 'Sub-Total', '30.0000', 1),
(69, 22, 'shipping', 'Pick-up', '0.0000', 3),
(70, 22, 'total', 'Total', '30.0000', 9),
(71, 23, 'sub_total', 'Sub-Total', '21.0000', 1),
(72, 23, 'shipping', 'Pick-up', '0.0000', 3),
(73, 23, 'total', 'Total', '21.0000', 9),
(74, 24, 'sub_total', 'Sub-Total', '39.9000', 1),
(75, 24, 'shipping', 'Pick-up', '0.0000', 3),
(76, 24, 'total', 'Total', '39.9000', 9),
(77, 25, 'sub_total', 'Sub-Total', '26.0000', 1),
(78, 25, 'shipping', 'Pick-up', '0.0000', 3),
(79, 25, 'total', 'Total', '26.0000', 9),
(80, 26, 'sub_total', 'Sub-Total', '109.3000', 1),
(81, 26, 'shipping', 'Pick-up', '0.0000', 3),
(82, 26, 'total', 'Total', '109.3000', 9),
(83, 27, 'sub_total', 'Sub-Total', '13.0000', 1),
(84, 27, 'shipping', 'Pick-up', '0.0000', 3),
(85, 27, 'total', 'Total', '13.0000', 9),
(86, 28, 'sub_total', 'Sub-Total', '7.0000', 1),
(87, 28, 'shipping', 'Pick-up', '0.0000', 3),
(88, 28, 'low_order_fee', 'Additional charges', '3.0000', 8),
(89, 28, 'total', 'Total', '10.0000', 9),
(90, 29, 'sub_total', 'Sub-Total', '3.5000', 1),
(91, 29, 'shipping', 'Pick-up', '0.0000', 3),
(92, 29, 'low_order_fee', 'Additional charges', '6.5000', 8),
(93, 29, 'total', 'Total', '10.0000', 9),
(94, 30, 'sub_total', 'Sub-Total', '19.9000', 1),
(95, 30, 'shipping', 'Pick-up', '0.0000', 3),
(96, 30, 'total', 'Total', '19.9000', 9),
(97, 31, 'sub_total', 'Sub-Total', '11.0000', 1),
(98, 31, 'shipping', 'Pick-up', '0.0000', 3),
(99, 31, 'total', 'Total', '11.0000', 9),
(100, 32, 'sub_total', 'Sub-Total', '5.9000', 1),
(101, 32, 'shipping', 'Pick-up', '0.0000', 3),
(102, 32, 'low_order_fee', 'Additional charges', '4.1000', 8),
(103, 32, 'total', 'Total', '10.0000', 9),
(104, 33, 'sub_total', 'Sub-Total', '17.7000', 1),
(105, 33, 'shipping', 'Pick-up', '0.0000', 3),
(106, 33, 'total', 'Total', '17.7000', 9),
(107, 34, 'sub_total', 'Sub-Total', '30.0000', 1),
(108, 34, 'shipping', 'Pick-up', '0.0000', 3),
(109, 34, 'total', 'Total', '30.0000', 9),
(110, 35, 'sub_total', 'Sub-Total', '19.9000', 1),
(111, 35, 'shipping', 'Pick-up', '0.0000', 3),
(112, 35, 'total', 'Total', '19.9000', 9),
(113, 36, 'sub_total', 'Sub-Total', '12.9000', 1),
(114, 36, 'shipping', 'Pick-up', '0.0000', 3),
(115, 36, 'total', 'Total', '12.9000', 9),
(116, 37, 'sub_total', 'Sub-Total', '17.9000', 1),
(117, 37, 'shipping', 'Pick-up', '0.0000', 3),
(118, 37, 'total', 'Total', '17.9000', 9),
(119, 38, 'sub_total', 'Sub-Total', '12.9000', 1),
(120, 38, 'shipping', 'Pick-up', '0.0000', 3),
(121, 38, 'total', 'Total', '12.9000', 9),
(122, 39, 'sub_total', 'Sub-Total', '19.9000', 1),
(123, 39, 'shipping', 'Pick-up', '0.0000', 3),
(124, 39, 'total', 'Total', '19.9000', 9),
(125, 40, 'sub_total', 'Sub-Total', '20.9000', 1),
(126, 40, 'shipping', 'Pick-up', '0.0000', 3),
(127, 40, 'total', 'Total', '20.9000', 9),
(128, 41, 'sub_total', 'Sub-Total', '35.8000', 1),
(129, 41, 'shipping', 'Pick-up', '0.0000', 3),
(130, 41, 'total', 'Total', '35.8000', 9),
(131, 42, 'sub_total', 'Sub-Total', '19.9000', 1),
(132, 42, 'shipping', 'Pick-up', '0.0000', 3),
(133, 42, 'total', 'Total', '19.9000', 9),
(134, 43, 'sub_total', 'Sub-Total', '62.9000', 1),
(135, 43, 'shipping', 'Pick-up', '0.0000', 3),
(136, 43, 'total', 'Total', '62.9000', 9),
(137, 44, 'sub_total', 'Sub-Total', '62.9000', 1),
(138, 44, 'shipping', 'Pick-up', '0.0000', 3),
(139, 44, 'total', 'Total', '62.9000', 9),
(140, 45, 'sub_total', 'Sub-Total', '62.9000', 1),
(141, 45, 'shipping', 'Pick-up', '0.0000', 3),
(142, 45, 'total', 'Total', '62.9000', 9),
(143, 46, 'sub_total', 'Sub-Total', '19.8000', 1),
(144, 46, 'shipping', 'Pick-up', '0.0000', 3),
(145, 46, 'total', 'Total', '19.8000', 9),
(146, 47, 'sub_total', 'Sub-Total', '11.0000', 1),
(147, 47, 'shipping', 'Pick-up', '0.0000', 3),
(148, 47, 'total', 'Total', '11.0000', 9),
(149, 48, 'sub_total', 'Sub-Total', '28.7000', 1),
(150, 48, 'shipping', 'Pick-up', '0.0000', 3),
(151, 48, 'total', 'Total', '28.7000', 9),
(152, 49, 'sub_total', 'Sub-Total', '36.7000', 1),
(153, 49, 'shipping', 'Pick-up', '0.0000', 3),
(154, 49, 'total', 'Total', '36.7000', 9),
(155, 50, 'sub_total', 'Sub-Total', '19.9000', 1),
(156, 50, 'shipping', 'Pick-up', '0.0000', 3),
(157, 50, 'total', 'Total', '19.9000', 9),
(158, 51, 'sub_total', 'Sub-Total', '19.9000', 1),
(159, 51, 'shipping', 'Pick-up', '0.0000', 3),
(160, 51, 'total', 'Total', '19.9000', 9),
(161, 52, 'sub_total', 'Sub-Total', '20.9000', 1),
(162, 52, 'shipping', 'Pick-up', '0.0000', 3),
(163, 52, 'total', 'Total', '20.9000', 9),
(164, 53, 'sub_total', 'Sub-Total', '28.9000', 1),
(165, 53, 'shipping', 'Pick-up', '0.0000', 3),
(166, 53, 'total', 'Total', '28.9000', 9),
(167, 54, 'sub_total', 'Sub-Total', '19.9000', 1),
(168, 54, 'shipping', 'Pick-up', '0.0000', 3),
(169, 54, 'total', 'Total', '19.9000', 9),
(170, 55, 'sub_total', 'Sub-Total', '15.0000', 1),
(171, 55, 'shipping', 'Pick-up', '0.0000', 3),
(172, 55, 'total', 'Total', '15.0000', 9),
(173, 56, 'sub_total', 'Sub-Total', '16.9000', 1),
(174, 56, 'shipping', 'Pick-up', '0.0000', 3),
(175, 56, 'total', 'Total', '16.9000', 9),
(176, 57, 'sub_total', 'Sub-Total', '8.9000', 1),
(177, 57, 'shipping', 'Pick-up', '0.0000', 3),
(178, 57, 'low_order_fee', 'Additional charges', '1.1000', 8),
(179, 57, 'total', 'Total', '10.0000', 9),
(180, 58, 'sub_total', 'Sub-Total', '16.9000', 1),
(181, 58, 'shipping', 'Pick-up', '0.0000', 3),
(182, 58, 'total', 'Total', '16.9000', 9),
(183, 59, 'sub_total', 'Sub-Total', '8.9000', 1),
(184, 59, 'shipping', 'Pick-up', '0.0000', 3),
(185, 59, 'low_order_fee', 'Additional charges', '1.1000', 8),
(186, 59, 'total', 'Total', '10.0000', 9),
(187, 60, 'sub_total', 'Sub-Total', '17.9000', 1),
(188, 60, 'shipping', 'Pick-up', '0.0000', 3),
(189, 60, 'total', 'Total', '17.9000', 9),
(190, 61, 'sub_total', 'Sub-Total', '17.9000', 1),
(191, 61, 'shipping', 'Pick-up', '0.0000', 3),
(192, 61, 'total', 'Total', '17.9000', 9),
(193, 62, 'sub_total', 'Sub-Total', '18.9000', 1),
(194, 62, 'shipping', 'Pick-up', '0.0000', 3),
(195, 62, 'total', 'Total', '18.9000', 9),
(196, 63, 'sub_total', 'Sub-Total', '12.9000', 1),
(197, 63, 'shipping', 'Pick-up', '0.0000', 3),
(198, 63, 'total', 'Total', '12.9000', 9),
(199, 64, 'sub_total', 'Sub-Total', '10.9000', 1),
(200, 64, 'shipping', 'Pick-up', '0.0000', 3),
(201, 64, 'total', 'Total', '10.9000', 9),
(202, 65, 'sub_total', 'Sub-Total', '12.9000', 1),
(203, 65, 'shipping', 'Pick-up', '0.0000', 3),
(204, 65, 'total', 'Total', '12.9000', 9),
(205, 66, 'sub_total', 'Sub-Total', '17.9000', 1),
(206, 66, 'shipping', 'Pick-up', '0.0000', 3),
(207, 66, 'total', 'Total', '17.9000', 9),
(208, 67, 'sub_total', 'Sub-Total', '12.9000', 1),
(209, 67, 'shipping', 'Pick-up', '0.0000', 3),
(210, 67, 'total', 'Total', '12.9000', 9),
(211, 68, 'sub_total', 'Sub-Total', '22.9000', 1),
(212, 68, 'shipping', 'Pick-up', '0.0000', 3),
(213, 68, 'total', 'Total', '22.9000', 9),
(214, 69, 'sub_total', 'Sub-Total', '12.9000', 1),
(215, 69, 'shipping', 'Pick-up', '0.0000', 3),
(216, 69, 'total', 'Total', '12.9000', 9),
(217, 70, 'sub_total', 'Sub-Total', '39.8000', 1),
(218, 70, 'shipping', 'Pick-up', '0.0000', 3),
(219, 70, 'total', 'Total', '39.8000', 9),
(220, 71, 'sub_total', 'Sub-Total', '16.9000', 1),
(221, 71, 'shipping', 'Pick-up', '0.0000', 3),
(222, 71, 'total', 'Total', '16.9000', 9),
(223, 72, 'sub_total', 'Sub-Total', '12.9000', 1),
(224, 72, 'shipping', 'Delivery', '5.0000', 3),
(225, 72, 'total', 'Total', '17.9000', 9),
(226, 73, 'sub_total', 'Sub-Total', '12.9000', 1),
(227, 73, 'shipping', 'Delivery', '5.0000', 3),
(228, 73, 'total', 'Total', '17.9000', 9),
(229, 74, 'sub_total', 'Sub-Total', '26.9000', 1),
(230, 74, 'shipping', 'Pick-up', '0.0000', 3),
(231, 74, 'total', 'Total', '26.9000', 9),
(232, 75, 'sub_total', 'Sub-Total', '17.9000', 1),
(233, 75, 'shipping', 'Delivery', '5.0000', 3),
(234, 75, 'total', 'Total', '22.9000', 9),
(235, 76, 'sub_total', 'Sub-Total', '41.8000', 1),
(236, 76, 'shipping', 'Pick-up', '0.0000', 3),
(237, 76, 'total', 'Total', '41.8000', 9),
(238, 77, 'sub_total', 'Sub-Total', '26.9000', 1),
(239, 77, 'shipping', 'Delivery', '3.0000', 3),
(240, 77, 'total', 'Total', '29.9000', 9),
(241, 78, 'sub_total', 'Sub-Total', '26.9000', 1),
(242, 78, 'shipping', 'Delivery', '3.0000', 3),
(243, 78, 'total', 'Total', '29.9000', 9),
(244, 79, 'sub_total', 'Sub-Total', '17.9000', 1),
(245, 79, 'shipping', 'Delivery', '3.0000', 3),
(246, 79, 'total', 'Total', '20.9000', 9),
(247, 80, 'sub_total', 'Sub-Total', '17.9000', 1),
(248, 80, 'shipping', 'Pick-up', '0.0000', 3),
(249, 80, 'total', 'Total', '17.9000', 9),
(250, 81, 'sub_total', 'Sub-Total', '26.9000', 1),
(251, 81, 'shipping', 'Delivery', '5.0000', 3),
(252, 81, 'total', 'Total', '31.9000', 9),
(253, 82, 'sub_total', 'Sub-Total', '8.9000', 1),
(254, 82, 'shipping', 'Delivery', '5.0000', 3),
(255, 82, 'low_order_fee', 'Additional charges', '1.1000', 8),
(256, 82, 'total', 'Total', '15.0000', 9),
(257, 83, 'sub_total', 'Sub-Total', '17.9000', 1),
(258, 83, 'shipping', 'Delivery', '5.0000', 3),
(259, 83, 'total', 'Total', '22.9000', 9),
(260, 84, 'sub_total', 'Sub-Total', '26.9000', 1),
(261, 84, 'shipping', 'Pick-up', '0.0000', 3),
(262, 84, 'total', 'Total', '26.9000', 9),
(263, 85, 'sub_total', 'Sub-Total', '16.9000', 1),
(264, 85, 'shipping', 'Pick-up', '0.0000', 3),
(265, 85, 'total', 'Total', '16.9000', 9),
(266, 86, 'sub_total', 'Sub-Total', '16.9000', 1),
(267, 86, 'shipping', 'Delivery', '6.0000', 3),
(268, 86, 'total', 'Total', '22.9000', 9),
(269, 87, 'sub_total', 'Sub-Total', '26.9000', 1),
(270, 87, 'shipping', 'Pick-up', '0.0000', 3),
(271, 87, 'total', 'Total', '26.9000', 9),
(272, 88, 'sub_total', 'Sub-Total', '12.9000', 1),
(273, 88, 'shipping', 'Pick-up', '0.0000', 3),
(274, 88, 'total', 'Total', '12.9000', 9),
(275, 89, 'sub_total', 'Sub-Total', '12.9000', 1),
(276, 89, 'shipping', 'Delivery', '5.0000', 3),
(277, 89, 'total', 'Total', '17.9000', 9),
(278, 90, 'sub_total', 'Sub-Total', '17.9000', 1),
(279, 90, 'shipping', 'Delivery', '3.0000', 3),
(280, 90, 'total', 'Total', '20.9000', 9),
(281, 91, 'sub_total', 'Sub-Total', '8.9000', 1),
(282, 91, 'shipping', 'Pick-up', '0.0000', 3),
(283, 91, 'low_order_fee', 'Additional charges', '1.1000', 8),
(284, 91, 'total', 'Total', '10.0000', 9),
(285, 92, 'sub_total', 'Sub-Total', '16.9000', 1),
(286, 92, 'shipping', 'Pick-up', '0.0000', 3),
(287, 92, 'total', 'Total', '16.9000', 9),
(288, 93, 'sub_total', 'Sub-Total', '16.9000', 1),
(289, 93, 'shipping', 'Pick-up', '0.0000', 3),
(290, 93, 'total', 'Total', '16.9000', 9),
(291, 94, 'sub_total', 'Sub-Total', '8.9000', 1),
(292, 94, 'shipping', 'Pick-up', '0.0000', 3),
(293, 94, 'low_order_fee', 'Additional charges', '1.1000', 8),
(294, 94, 'total', 'Total', '10.0000', 9),
(295, 95, 'sub_total', 'Sub-Total', '17.9000', 1),
(296, 95, 'shipping', 'Pick-up', '0.0000', 3),
(297, 95, 'total', 'Total', '17.9000', 9),
(298, 96, 'sub_total', 'Sub-Total', '22.9000', 1),
(299, 96, 'shipping', 'Pick-up', '0.0000', 3),
(300, 96, 'total', 'Total', '22.9000', 9),
(301, 97, 'sub_total', 'Sub-Total', '16.9000', 1),
(302, 97, 'shipping', 'Pick-up', '0.0000', 3),
(303, 97, 'total', 'Total', '16.9000', 9),
(304, 98, 'sub_total', 'Sub-Total', '17.9000', 1),
(305, 98, 'shipping', 'Delivery', '5.0000', 3),
(306, 98, 'total', 'Total', '22.9000', 9),
(307, 99, 'sub_total', 'Sub-Total', '16.9000', 1),
(308, 99, 'shipping', 'Pick-up', '0.0000', 3),
(309, 99, 'total', 'Total', '16.9000', 9),
(310, 100, 'sub_total', 'Sub-Total', '22.9000', 1),
(311, 100, 'shipping', 'Pick-up', '0.0000', 3),
(312, 100, 'total', 'Total', '22.9000', 9),
(313, 101, 'sub_total', 'Sub-Total', '22.9000', 1),
(314, 101, 'shipping', 'Pick-up', '0.0000', 3),
(315, 101, 'total', 'Total', '22.9000', 9),
(316, 102, 'sub_total', 'Sub-Total', '20.9000', 1),
(317, 102, 'shipping', 'Pick-up', '0.0000', 3),
(318, 102, 'total', 'Total', '20.9000', 9),
(319, 103, 'sub_total', 'Sub-Total', '22.9000', 1),
(320, 103, 'shipping', 'Pick-up', '0.0000', 3),
(321, 103, 'total', 'Total', '22.9000', 9),
(322, 104, 'sub_total', 'Sub-Total', '17.9000', 1),
(323, 104, 'shipping', 'Delivery', '6.0000', 3),
(324, 104, 'total', 'Total', '23.9000', 9),
(325, 105, 'sub_total', 'Sub-Total', '14.9000', 1),
(326, 105, 'shipping', 'Pick-up', '0.0000', 3),
(327, 105, 'total', 'Total', '14.9000', 9),
(328, 106, 'sub_total', 'Sub-Total', '15.0000', 1),
(329, 106, 'shipping', 'Delivery', '6.0000', 3),
(330, 106, 'total', 'Total', '21.0000', 9),
(331, 107, 'sub_total', 'Sub-Total', '19.9000', 1),
(332, 107, 'shipping', 'Delivery', '5.0000', 3),
(333, 107, 'total', 'Total', '24.9000', 9),
(334, 108, 'sub_total', 'Sub-Total', '26.9000', 1),
(335, 108, 'shipping', 'Delivery', '5.0000', 3),
(336, 108, 'total', 'Total', '31.9000', 9),
(337, 109, 'sub_total', 'Sub-Total', '39.9000', 1),
(338, 109, 'shipping', 'Delivery', '6.0000', 3),
(339, 109, 'total', 'Total', '45.9000', 9),
(340, 110, 'sub_total', 'Sub-Total', '39.9000', 1),
(341, 110, 'shipping', 'Delivery', '6.0000', 3),
(342, 110, 'total', 'Total', '45.9000', 9),
(343, 111, 'sub_total', 'Sub-Total', '39.9000', 1),
(344, 111, 'shipping', 'Delivery', '6.0000', 3),
(345, 111, 'total', 'Total', '45.9000', 9),
(346, 112, 'sub_total', 'Sub-Total', '18.9000', 1),
(347, 112, 'shipping', 'Delivery', '5.0000', 3),
(348, 112, 'total', 'Total', '23.9000', 9),
(349, 113, 'sub_total', 'Sub-Total', '26.9000', 1),
(350, 113, 'shipping', 'Delivery', '5.0000', 3),
(351, 113, 'total', 'Total', '31.9000', 9),
(352, 114, 'sub_total', 'Sub-Total', '11.0000', 1),
(353, 114, 'shipping', 'Delivery', '5.0000', 3),
(354, 114, 'total', 'Total', '16.0000', 9),
(355, 115, 'sub_total', 'Sub-Total', '26.9000', 1),
(356, 115, 'shipping', 'Delivery', '6.0000', 3),
(357, 115, 'total', 'Total', '32.9000', 9),
(358, 116, 'sub_total', 'Sub-Total', '24.9000', 1),
(359, 116, 'shipping', 'Delivery', '6.0000', 3),
(360, 116, 'total', 'Total', '30.9000', 9),
(361, 117, 'sub_total', 'Sub-Total', '5.9000', 1),
(362, 117, 'shipping', 'Delivery', '6.0000', 3),
(363, 117, 'low_order_fee', 'Additional charges', '4.1000', 8),
(364, 117, 'total', 'Total', '16.0000', 9),
(365, 118, 'sub_total', 'Sub-Total', '5.9000', 1),
(366, 118, 'shipping', 'Delivery', '6.0000', 3),
(367, 118, 'low_order_fee', 'Additional charges', '4.1000', 8),
(368, 118, 'total', 'Total', '16.0000', 9),
(369, 119, 'sub_total', 'Sub-Total', '24.9000', 1),
(370, 119, 'shipping', 'Delivery', '6.0000', 3),
(371, 119, 'total', 'Total', '30.9000', 9),
(372, 120, 'sub_total', 'Sub-Total', '24.9000', 1),
(373, 120, 'shipping', 'Delivery', '6.0000', 3),
(374, 120, 'total', 'Total', '30.9000', 9),
(375, 121, 'sub_total', 'Sub-Total', '24.9000', 1),
(376, 121, 'shipping', 'Delivery', '6.0000', 3),
(377, 121, 'total', 'Total', '30.9000', 9),
(378, 122, 'sub_total', 'Sub-Total', '8.9000', 1),
(379, 122, 'shipping', 'Delivery', '6.0000', 3),
(380, 122, 'low_order_fee', 'Additional charges', '1.1000', 8),
(381, 122, 'total', 'Total', '16.0000', 9),
(382, 123, 'sub_total', 'Sub-Total', '20.9000', 1),
(383, 123, 'shipping', 'Delivery', '6.0000', 3),
(384, 123, 'total', 'Total', '26.9000', 9),
(385, 124, 'sub_total', 'Sub-Total', '16.9000', 1),
(386, 124, 'shipping', 'Delivery', '6.0000', 3),
(387, 124, 'total', 'Total', '22.9000', 9),
(388, 125, 'sub_total', 'Sub-Total', '16.9000', 1),
(389, 125, 'shipping', 'Delivery', '6.0000', 3),
(390, 125, 'total', 'Total', '22.9000', 9),
(391, 126, 'sub_total', 'Sub-Total', '5.0000', 1),
(392, 126, 'shipping', 'Delivery', '0.0000', 3),
(393, 126, 'low_order_fee', 'Additional charges', '5.0000', 8),
(394, 126, 'total', 'Total', '10.0000', 9),
(395, 127, 'sub_total', 'Sub-Total', '18.9000', 1),
(396, 127, 'shipping', 'Pick-up', '0.0000', 3),
(397, 127, 'total', 'Total', '18.9000', 9),
(398, 128, 'sub_total', 'Sub-Total', '0.0000', 1),
(399, 128, 'shipping', 'Pick-up', '0.0000', 3),
(400, 128, 'low_order_fee', 'Additional charges', '10.0000', 8),
(401, 128, 'total', 'Total', '10.0000', 9),
(402, 129, 'sub_total', 'Sub-Total', '18.9000', 1),
(403, 129, 'shipping', 'Pick-up', '0.0000', 3),
(404, 129, 'total', 'Total', '18.9000', 9),
(405, 130, 'sub_total', 'Sub-Total', '5.0000', 1),
(406, 130, 'shipping', 'Pick-up', '0.0000', 3),
(407, 130, 'low_order_fee', 'Additional charges', '5.0000', 8),
(408, 130, 'total', 'Total', '10.0000', 9),
(409, 131, 'sub_total', 'Sub-Total', '5.9000', 1),
(410, 131, 'shipping', 'Pick-up', '0.0000', 3),
(411, 131, 'low_order_fee', 'Additional charges', '4.1000', 8),
(412, 131, 'total', 'Total', '10.0000', 9),
(413, 132, 'sub_total', 'Sub-Total', '5.0000', 1),
(414, 132, 'shipping', 'Pick-up', '0.0000', 3),
(415, 132, 'low_order_fee', 'Additional charges', '5.0000', 8),
(416, 132, 'total', 'Total', '10.0000', 9),
(417, 133, 'sub_total', 'Sub-Total', '9.9000', 1),
(418, 133, 'shipping', 'Pick-up', '0.0000', 3),
(419, 133, 'low_order_fee', 'Additional charges', '0.1000', 8),
(420, 133, 'total', 'Total', '10.0000', 9),
(421, 134, 'sub_total', 'Sub-Total', '17.8000', 1),
(422, 134, 'shipping', 'Pick-up', '0.0000', 3),
(423, 134, 'total', 'Total', '17.8000', 9),
(424, 135, 'sub_total', 'Sub-Total', '5.0000', 1),
(425, 135, 'shipping', 'Pick-up', '0.0000', 3),
(426, 135, 'low_order_fee', 'Additional charges', '5.0000', 8),
(427, 135, 'total', 'Total', '10.0000', 9),
(428, 136, 'sub_total', 'Sub-Total', '26.9000', 1),
(429, 136, 'shipping', 'Pick-up', '0.0000', 3),
(430, 136, 'total', 'Total', '26.9000', 9),
(431, 137, 'sub_total', 'Sub-Total', '8.9000', 1),
(432, 137, 'shipping', 'Pick-up', '0.0000', 3),
(433, 137, 'low_order_fee', 'Additional charges', '1.1000', 8),
(434, 137, 'total', 'Total', '10.0000', 9),
(435, 138, 'sub_total', 'Sub-Total', '4.8000', 1),
(436, 138, 'shipping', 'Pick-up', '0.0000', 3),
(437, 138, 'low_order_fee', 'Additional charges', '5.2000', 8),
(438, 138, 'total', 'Total', '10.0000', 9),
(439, 139, 'sub_total', 'Sub-Total', '10.9000', 1),
(440, 139, 'shipping', 'Pick-up', '0.0000', 3),
(441, 139, 'total', 'Total', '10.9000', 9),
(442, 140, 'sub_total', 'Sub-Total', '18.8000', 1),
(443, 140, 'shipping', 'Pick-up', '0.0000', 3),
(444, 140, 'total', 'Total', '18.8000', 9),
(445, 141, 'sub_total', 'Sub-Total', '26.8000', 1),
(446, 141, 'shipping', 'Pick-up', '0.0000', 3),
(447, 141, 'total', 'Total', '26.8000', 9),
(448, 142, 'sub_total', 'Sub-Total', '18.8000', 1),
(449, 142, 'shipping', 'Pick-up', '0.0000', 3),
(450, 142, 'total', 'Total', '18.8000', 9),
(451, 143, 'sub_total', 'Sub-Total', '3.0000', 1),
(452, 143, 'shipping', 'Pick-up', '0.0000', 3),
(453, 143, 'low_order_fee', 'Additional charges', '7.0000', 8),
(454, 143, 'total', 'Total', '10.0000', 9),
(455, 144, 'sub_total', 'Sub-Total', '15.0000', 1),
(456, 144, 'shipping', 'Pick-up', '0.0000', 3),
(457, 144, 'total', 'Total', '15.0000', 9),
(458, 145, 'sub_total', 'Sub-Total', '4.8000', 1),
(459, 145, 'shipping', 'Pick-up', '0.0000', 3),
(460, 145, 'low_order_fee', 'Additional charges', '5.2000', 8),
(461, 145, 'total', 'Total', '10.0000', 9),
(462, 146, 'sub_total', 'Sub-Total', '15.0000', 1),
(463, 146, 'shipping', 'Pick-up', '0.0000', 3),
(464, 146, 'total', 'Total', '15.0000', 9);

-- --------------------------------------------------------

--
-- 表的结构 `oc_order_voucher`
--

CREATE TABLE `oc_order_voucher` (
  `order_voucher_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `voucher_id` int(11) NOT NULL,
  `description` varchar(255) NOT NULL,
  `code` varchar(10) NOT NULL,
  `from_name` varchar(64) NOT NULL,
  `from_email` varchar(96) NOT NULL,
  `to_name` varchar(64) NOT NULL,
  `to_email` varchar(96) NOT NULL,
  `voucher_theme_id` int(11) NOT NULL,
  `message` text NOT NULL,
  `amount` decimal(15,4) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_paypal_order`
--

CREATE TABLE `oc_paypal_order` (
  `paypal_order_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `capture_status` enum('Complete','NotComplete') DEFAULT NULL,
  `currency_code` char(3) NOT NULL,
  `authorization_id` varchar(30) NOT NULL,
  `total` decimal(10,2) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_paypal_order_transaction`
--

CREATE TABLE `oc_paypal_order_transaction` (
  `paypal_order_transaction_id` int(11) NOT NULL,
  `paypal_order_id` int(11) NOT NULL,
  `transaction_id` char(20) NOT NULL,
  `parent_transaction_id` char(20) NOT NULL,
  `date_added` datetime NOT NULL,
  `note` varchar(255) NOT NULL,
  `msgsubid` char(38) NOT NULL,
  `receipt_id` char(20) NOT NULL,
  `payment_type` enum('none','echeck','instant','refund','void') DEFAULT NULL,
  `payment_status` char(20) NOT NULL,
  `pending_reason` char(50) NOT NULL,
  `transaction_entity` char(50) NOT NULL,
  `amount` decimal(10,2) NOT NULL,
  `debug_data` text NOT NULL,
  `call_data` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product`
--

CREATE TABLE `oc_product` (
  `product_id` int(11) NOT NULL,
  `model` varchar(64) NOT NULL,
  `sku` varchar(64) NOT NULL,
  `upc` varchar(12) NOT NULL,
  `ean` varchar(14) NOT NULL,
  `jan` varchar(13) NOT NULL,
  `isbn` varchar(17) NOT NULL,
  `mpn` varchar(64) NOT NULL,
  `location` varchar(128) NOT NULL,
  `quantity` int(4) NOT NULL DEFAULT '0',
  `sold_quantity` int(11) NOT NULL,
  `stock_status_id` int(11) NOT NULL,
  `image` varchar(255) DEFAULT NULL,
  `manufacturer_id` int(11) NOT NULL,
  `shipping` tinyint(1) NOT NULL DEFAULT '1',
  `price` decimal(15,4) NOT NULL DEFAULT '0.0000',
  `points` int(8) NOT NULL DEFAULT '0',
  `tax_class_id` int(11) NOT NULL,
  `date_available` date NOT NULL DEFAULT '0000-00-00',
  `weight` decimal(15,8) NOT NULL DEFAULT '0.00000000',
  `weight_class_id` int(11) NOT NULL DEFAULT '0',
  `length` decimal(15,8) NOT NULL DEFAULT '0.00000000',
  `width` decimal(15,8) NOT NULL DEFAULT '0.00000000',
  `height` decimal(15,8) NOT NULL DEFAULT '0.00000000',
  `length_class_id` int(11) NOT NULL DEFAULT '0',
  `subtract` tinyint(1) NOT NULL DEFAULT '1',
  `minimum` int(11) NOT NULL DEFAULT '1',
  `sort_order` int(11) NOT NULL DEFAULT '0',
  `status` tinyint(1) NOT NULL DEFAULT '0',
  `viewed` int(5) NOT NULL DEFAULT '0',
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL,
  `product_tags` varchar(20) NOT NULL,
  `is_discount` tinyint(1) NOT NULL DEFAULT '1'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product`
--

INSERT INTO `oc_product` (`product_id`, `model`, `sku`, `upc`, `ean`, `jan`, `isbn`, `mpn`, `location`, `quantity`, `sold_quantity`, `stock_status_id`, `image`, `manufacturer_id`, `shipping`, `price`, `points`, `tax_class_id`, `date_available`, `weight`, `weight_class_id`, `length`, `width`, `height`, `length_class_id`, `subtract`, `minimum`, `sort_order`, `status`, `viewed`, `date_added`, `date_modified`, `product_tags`, `is_discount`) VALUES
(24, '', '', '', '', '', '', '', '', 9999, 222, 0, '/images/products/24.jpeg', 0, 1, '2.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(23, '', '', '', '', '', '', '', '', 9999, 222, 0, '/images/products/23.jpeg', 0, 1, '2.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(20, '', '', '', '', '', '', '', '', 9999, 333, 0, '/images/products/20.jpeg', 0, 1, '3.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(19, '', '', '', '', '', '', '', '', 9999, 444, 0, '/images/products/19.jpeg', 0, 1, '10.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(18, '', '', '', '', '', '', '', '', 9999, 555, 0, '/images/products/18.jpeg', 0, 1, '10.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(17, '', '', '', '', '', '', '', '', 9999, 666, 0, '/images/products/17.jpeg', 0, 1, '10.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(16, '', '', '', '', '', '', '', '', 9999, 123, 0, '/images/products/16.jpeg', 0, 1, '10.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(15, '', '', '', '', '', '', '', '', 9999, 567, 0, '/images/products/15.jpeg', 0, 1, '3.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(14, '', '', '', '', '', '', '', '', 9999, 222, 0, '/images/products/14.jpeg', 0, 1, '3.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(13, '', '', '', '', '', '', '', '', 9999, 124, 0, '/images/products/13.jpeg', 0, 1, '10.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(12, '', '', '', '', '', '', '', '', 9999, 574, 0, '/images/products/12.jpeg', 0, 1, '10.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(11, '', '', '', '', '', '', '', '', 9999, 458, 0, '/images/products/11.jpeg', 0, 1, '10.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(10, '', '', '', '', '', '', '', '', 9999, 789, 0, '/images/products/10.jpeg', 0, 1, '7.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(9, '', '', '', '', '', '', '', '', 9999, 123, 0, '/images/products/9.jpeg', 0, 1, '10.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(8, '', '', '', '', '', '', '', '', 9999, 587, 0, '/images/products/8.jpeg', 0, 1, '12.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(7, '', '', '', '', '', '', '', '', 9999, 987, 0, '/images/products/7.jpeg', 0, 1, '12.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(6, '', '', '', '', '', '', '', '', 9999, 784, 0, '/images/products/6.jpeg', 0, 1, '12.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(5, '', '', '', '', '', '', '', '', 9999, 111, 0, '/images/products/5.jpeg', 0, 1, '12.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(4, '', '', '', '', '', '', '', '', 9999, 124, 0, '/images/products/4.jpeg', 0, 1, '12.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1),
(3, '', '', '', '', '', '', '', '', 9999, 873, 0, '/images/products/3.jpeg', 0, 0, '12.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 0, 0, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 0),
(2, '', '', '', '', '', '', '', '', 9999, 987, 0, '/images/products/2.jpeg', 0, 0, '12.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 0, 0, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 0),
(1, '', '', '', '', '', '', '', '', 9999, 456, 0, '/images/products/1.jpeg', 0, 1, '12.8000', 0, 0, '0000-00-00', '0.00000000', 0, '0.00000000', '0.00000000', '0.00000000', 0, 1, 1, 0, 0, 0, '0000-00-00 00:00:00', '0000-00-00 00:00:00', '', 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_add_type`
--

CREATE TABLE `oc_product_add_type` (
  `add_type_id` int(11) UNSIGNED NOT NULL,
  `name` varchar(255) NOT NULL,
  `language_id` int(11) NOT NULL,
  `type` tinyint(1) NOT NULL DEFAULT '0',
  `required` tinyint(1) NOT NULL DEFAULT '0',
  `checkbox` tinyint(1) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product_add_type`
--

INSERT INTO `oc_product_add_type` (`add_type_id`, `name`, `language_id`, `type`, `required`, `checkbox`) VALUES
(1, 'How Spicy', 1, 1, 1, 0),
(1, '辣度', 2, 1, 1, 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_attribute`
--

CREATE TABLE `oc_product_attribute` (
  `product_id` int(11) NOT NULL,
  `attribute_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `text` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_description`
--

CREATE TABLE `oc_product_description` (
  `product_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `description` text NOT NULL,
  `tag` text NOT NULL,
  `meta_title` varchar(255) NOT NULL,
  `meta_description` varchar(255) NOT NULL,
  `meta_keyword` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product_description`
--

INSERT INTO `oc_product_description` (`product_id`, `language_id`, `name`, `description`, `tag`, `meta_title`, `meta_description`, `meta_keyword`) VALUES
(23, 1, 'spirit', '', '', '', '', ''),
(24, 2, '芬达', '', '', '', '', ''),
(24, 1, 'fanta', '', '', '', '', ''),
(20, 2, '可乐', '', '', '', '', ''),
(20, 1, 'coke', '', '', '', '', ''),
(23, 2, '雪碧', '', '', '', '', ''),
(18, 1, 'prok chitterlings and peas with rice', '', '', '', '', ''),
(19, 2, '竹笋烧鸡套饭', '', '', '', '', ''),
(19, 1, 'chiken with bamboo shots with rice', '', '', '', '', ''),
(16, 1, 'spicy beef with rice', '', '', '', '', ''),
(17, 2, '红焖羊排套饭', '', '', '', '', ''),
(17, 1, 'lamb ribs with rice', '', '', '', '', ''),
(18, 2, '豌豆烧肥肠套饭', '', '', '', '', ''),
(16, 2, '红烧牛肉面套饭', '', '', '', '', ''),
(14, 1, 'sichuan cold noodle', '', '', '', '', ''),
(15, 2, '川北凉粉', '', '', '', '', ''),
(15, 1, 'spicy green-bean jelly noodles', '', '', '', '', ''),
(13, 1, 'beef potato noodles', '', '', '', '', ''),
(14, 2, '风味凉面', '', '', '', '', ''),
(12, 2, '杂酱酸辣粉', '', '', '', '', ''),
(12, 1, 'miniced pork potato noodles', '', '', '', '', ''),
(13, 2, '牛肉酸辣粉', '', '', '', '', ''),
(11, 1, 'pork chitterlings potato noodels', '', '', '', '', ''),
(10, 2, '酸辣粉', '', '', '', '', ''),
(10, 1, 'potato noodle', '', '', '', '', ''),
(11, 2, '肥肠酸辣粉', '', '', '', '', ''),
(7, 1, 'fish with pickled vegetable', '', '', '', '', ''),
(8, 2, '菌王鸡汤面', '', '', '', '', ''),
(8, 1, 'mountain mushrooms', '', '', '', '', ''),
(9, 2, '重庆麻辣小面', '', '', '', '', ''),
(9, 1, 'chongqing spicky noodle', '', '', '', '', ''),
(6, 1, 'pork balls with tomato', '', '', '', '', ''),
(7, 2, '酸菜鱼面', '', '', '', '', ''),
(6, 2, '番茄丸子面', '', '', '', '', ''),
(4, 2, '竹笋烧鸡面', '', '', '', '', ''),
(5, 2, '豌豆肥肠面', '', '', '', '', ''),
(5, 1, 'Pork chitterlings with peas', '', '', '', '', ''),
(4, 1, 'Chicken With Bamboo Shoots', '', '', '', '', ''),
(3, 2, '豌豆杂酱面', '', '', '', '', ''),
(3, 1, 'Minced Pork With Peas', '', '', '', '', ''),
(2, 2, '红焖羊肉面', '', '', '', '', ''),
(2, 1, 'Stewed Lamb Ribs Noodle', '', '', '', '', ''),
(1, 1, 'Spicy Stewed Beef Noodles Soup', '', '', '', '', ''),
(1, 2, '麻辣牛肉面', '', '', '', '', '');

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_discount`
--

CREATE TABLE `oc_product_discount` (
  `product_discount_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `customer_group_id` int(11) NOT NULL,
  `quantity` int(4) NOT NULL DEFAULT '0',
  `priority` int(5) NOT NULL DEFAULT '1',
  `price` decimal(15,4) NOT NULL DEFAULT '0.0000',
  `date_start` date NOT NULL DEFAULT '0000-00-00',
  `date_end` date NOT NULL DEFAULT '0000-00-00'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_ext`
--

CREATE TABLE `oc_product_ext` (
  `product_ext_id` int(11) UNSIGNED NOT NULL,
  `language_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `type` int(11) NOT NULL,
  `name` varchar(128) NOT NULL,
  `price` decimal(10,2) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product_ext`
--

INSERT INTO `oc_product_ext` (`product_ext_id`, `language_id`, `product_id`, `type`, `name`, `price`) VALUES
(1, 2, 10, 1, '微辣', '0.00'),
(2, 2, 10, 1, '中辣', '0.00'),
(3, 2, 10, 1, '大辣', '0.00'),
(4, 2, 9, 1, '微辣', '0.00'),
(5, 2, 9, 1, '中辣', '0.00'),
(6, 2, 9, 1, '大辣', '0.00'),
(7, 2, 1, 1, '微辣', '0.00'),
(8, 2, 1, 1, '中辣', '0.00'),
(9, 2, 1, 1, '大辣', '0.00');

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_filter`
--

CREATE TABLE `oc_product_filter` (
  `product_id` int(11) NOT NULL,
  `filter_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_image`
--

CREATE TABLE `oc_product_image` (
  `product_image_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `image` varchar(255) DEFAULT NULL,
  `sort_order` int(3) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_option`
--

CREATE TABLE `oc_product_option` (
  `product_option_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `option_id` int(11) NOT NULL,
  `value` text NOT NULL,
  `required` tinyint(1) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product_option`
--

INSERT INTO `oc_product_option` (`product_option_id`, `product_id`, `option_id`, `value`, `required`) VALUES
(1, 323, 1, '', 0),
(7, 1, 5, '', 0),
(4, 324, 1, '', 1),
(8, 325, 5, '', 0),
(6, 1, 4, '', 0),
(5, 325, 3, '', 0),
(9, 326, 5, '', 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_option_value`
--

CREATE TABLE `oc_product_option_value` (
  `product_option_value_id` int(11) NOT NULL,
  `product_option_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `option_id` int(11) NOT NULL,
  `option_value_id` int(11) NOT NULL,
  `quantity` int(3) NOT NULL,
  `subtract` tinyint(1) NOT NULL,
  `price` decimal(15,4) NOT NULL,
  `price_prefix` varchar(1) NOT NULL,
  `points` int(8) NOT NULL,
  `points_prefix` varchar(1) NOT NULL,
  `weight` decimal(15,8) NOT NULL,
  `weight_prefix` varchar(1) NOT NULL,
  `display` tinyint(1) DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product_option_value`
--

INSERT INTO `oc_product_option_value` (`product_option_value_id`, `product_option_id`, `product_id`, `option_id`, `option_value_id`, `quantity`, `subtract`, `price`, `price_prefix`, `points`, `points_prefix`, `weight`, `weight_prefix`, `display`) VALUES
(34, 1, 2, 2, 3, 1, 0, '2.0000', '', 0, '', '0.00000000', '', NULL),
(33, 1, 1, 2, 3, 1, 0, '2.0000', '', 0, '', '0.00000000', '', NULL),
(32, 1, 1, 1, 2, 1, 0, '2.0000', '', 0, '', '0.00000000', '', NULL),
(31, 1, 2, 1, 2, 1, 0, '2.0000', '', 0, '', '0.00000000', '', NULL),
(2, 1, 2, 1, 1, 1, 0, '2.0000', '', 0, '', '0.00000000', '', NULL),
(1, 1, 1, 1, 1, 1, 0, '2.0000', '', 0, '', '0.00000000', '', NULL);

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_recurring`
--

CREATE TABLE `oc_product_recurring` (
  `product_id` int(11) NOT NULL,
  `recurring_id` int(11) NOT NULL,
  `customer_group_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_related`
--

CREATE TABLE `oc_product_related` (
  `product_id` int(11) NOT NULL,
  `related_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_reward`
--

CREATE TABLE `oc_product_reward` (
  `product_reward_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL DEFAULT '0',
  `customer_group_id` int(11) NOT NULL DEFAULT '0',
  `points` int(8) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_special`
--

CREATE TABLE `oc_product_special` (
  `product_special_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `customer_group_id` int(11) NOT NULL,
  `priority` int(5) NOT NULL DEFAULT '1',
  `price` decimal(15,4) NOT NULL DEFAULT '0.0000',
  `date_start` date NOT NULL DEFAULT '0000-00-00',
  `date_end` date NOT NULL DEFAULT '0000-00-00'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_tag`
--

CREATE TABLE `oc_product_tag` (
  `product_tag_id` int(11) UNSIGNED NOT NULL COMMENT '属性id',
  `name` varchar(32) NOT NULL COMMENT '属性名称',
  `sort` int(11) UNSIGNED NOT NULL DEFAULT '0' COMMENT '属性排序',
  `addtime` datetime NOT NULL COMMENT '添加时间',
  `status` tinyint(1) NOT NULL DEFAULT '1' COMMENT '状态'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product_tag`
--

INSERT INTO `oc_product_tag` (`product_tag_id`, `name`, `sort`, `addtime`, `status`) VALUES
(1, 'popular', 0, '2017-04-25 09:48:51', 1),
(2, 'hot', 0, '2017-04-25 09:52:03', 1),
(3, 'veg', 0, '2017-04-25 09:52:13', 1),
(4, 'health', 0, '2017-04-25 09:52:22', 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_to_category`
--

CREATE TABLE `oc_product_to_category` (
  `product_id` int(11) NOT NULL,
  `category_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product_to_category`
--

INSERT INTO `oc_product_to_category` (`product_id`, `category_id`) VALUES
(1, 1),
(2, 1),
(3, 1),
(4, 1),
(5, 1),
(6, 1),
(7, 1),
(8, 1),
(9, 1),
(10, 2),
(11, 2),
(12, 2),
(13, 2),
(14, 2),
(15, 2),
(16, 3),
(17, 3),
(18, 3),
(19, 3),
(20, 4),
(23, 4),
(24, 4);

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_to_download`
--

CREATE TABLE `oc_product_to_download` (
  `product_id` int(11) NOT NULL,
  `download_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_to_layout`
--

CREATE TABLE `oc_product_to_layout` (
  `product_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL,
  `layout_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product_to_layout`
--

INSERT INTO `oc_product_to_layout` (`product_id`, `store_id`, `layout_id`) VALUES
(139, 0, 0),
(132, 0, 0),
(1, 0, 0),
(2, 0, 0),
(3, 0, 0),
(4, 0, 0),
(6, 0, 0),
(5, 0, 0),
(7, 0, 0),
(9, 0, 0),
(12, 0, 0),
(13, 0, 0),
(297, 0, 0),
(16, 0, 0),
(17, 0, 0),
(20, 0, 0),
(22, 0, 0),
(18, 0, 0),
(19, 0, 0),
(21, 0, 0),
(23, 0, 0),
(24, 0, 0),
(27, 0, 0),
(28, 0, 0),
(29, 0, 0),
(25, 0, 0),
(26, 0, 0),
(37, 0, 0),
(38, 0, 0),
(39, 0, 0),
(41, 0, 0),
(43, 0, 0),
(45, 0, 0),
(46, 0, 0),
(47, 0, 0),
(44, 0, 0),
(48, 0, 0),
(50, 0, 0),
(54, 0, 0),
(53, 0, 0),
(49, 0, 0),
(51, 0, 0),
(52, 0, 0),
(58, 0, 0),
(57, 0, 0),
(60, 0, 0),
(55, 0, 0),
(59, 0, 0),
(61, 0, 0),
(56, 0, 0),
(322, 0, 0),
(66, 0, 0),
(68, 0, 0),
(69, 0, 0),
(70, 0, 0),
(72, 0, 0),
(71, 0, 0),
(300, 0, 0),
(323, 0, 0),
(324, 0, 0),
(325, 0, 0),
(326, 0, 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_product_to_store`
--

CREATE TABLE `oc_product_to_store` (
  `product_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_product_to_store`
--

INSERT INTO `oc_product_to_store` (`product_id`, `store_id`) VALUES
(1, 0),
(2, 0),
(3, 0),
(4, 0),
(5, 0),
(6, 0),
(7, 0),
(9, 0),
(12, 0),
(13, 0),
(16, 0),
(17, 0),
(18, 0),
(19, 0),
(20, 0),
(21, 0),
(22, 0),
(23, 0),
(24, 0),
(25, 0),
(26, 0),
(27, 0),
(28, 0),
(29, 0),
(37, 0),
(38, 0),
(39, 0),
(41, 0),
(43, 0),
(44, 0),
(45, 0),
(46, 0),
(47, 0),
(48, 0),
(49, 0),
(50, 0),
(51, 0),
(52, 0),
(53, 0),
(54, 0),
(55, 0),
(56, 0),
(57, 0),
(58, 0),
(59, 0),
(60, 0),
(61, 0),
(66, 0),
(68, 0),
(69, 0),
(70, 0),
(71, 0),
(72, 0),
(132, 0),
(139, 0),
(297, 0),
(300, 0),
(322, 0),
(323, 0),
(324, 0),
(325, 0),
(326, 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_recurring`
--

CREATE TABLE `oc_recurring` (
  `recurring_id` int(11) NOT NULL,
  `price` decimal(10,4) NOT NULL,
  `frequency` enum('day','week','semi_month','month','year') NOT NULL,
  `duration` int(10) UNSIGNED NOT NULL,
  `cycle` int(10) UNSIGNED NOT NULL,
  `trial_status` tinyint(4) NOT NULL,
  `trial_price` decimal(10,4) NOT NULL,
  `trial_frequency` enum('day','week','semi_month','month','year') NOT NULL,
  `trial_duration` int(10) UNSIGNED NOT NULL,
  `trial_cycle` int(10) UNSIGNED NOT NULL,
  `status` tinyint(4) NOT NULL,
  `sort_order` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_recurring_description`
--

CREATE TABLE `oc_recurring_description` (
  `recurring_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_return`
--

CREATE TABLE `oc_return` (
  `return_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `firstname` varchar(32) NOT NULL,
  `lastname` varchar(32) NOT NULL,
  `email` varchar(96) NOT NULL,
  `telephone` varchar(32) NOT NULL,
  `product` varchar(255) NOT NULL,
  `model` varchar(64) NOT NULL,
  `quantity` int(4) NOT NULL,
  `opened` tinyint(1) NOT NULL,
  `return_reason_id` int(11) NOT NULL,
  `return_action_id` int(11) NOT NULL,
  `return_status_id` int(11) NOT NULL,
  `comment` text,
  `date_ordered` date NOT NULL DEFAULT '0000-00-00',
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_return_action`
--

CREATE TABLE `oc_return_action` (
  `return_action_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL DEFAULT '0',
  `name` varchar(64) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_return_action`
--

INSERT INTO `oc_return_action` (`return_action_id`, `language_id`, `name`) VALUES
(1, 1, 'Refunded'),
(2, 1, 'Credit Issued'),
(3, 1, 'Replacement Sent');

-- --------------------------------------------------------

--
-- 表的结构 `oc_return_history`
--

CREATE TABLE `oc_return_history` (
  `return_history_id` int(11) NOT NULL,
  `return_id` int(11) NOT NULL,
  `return_status_id` int(11) NOT NULL,
  `notify` tinyint(1) NOT NULL,
  `comment` text NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_return_reason`
--

CREATE TABLE `oc_return_reason` (
  `return_reason_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL DEFAULT '0',
  `name` varchar(128) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_return_reason`
--

INSERT INTO `oc_return_reason` (`return_reason_id`, `language_id`, `name`) VALUES
(1, 1, 'Dead On Arrival'),
(2, 1, 'Received Wrong Item'),
(3, 1, 'Order Error'),
(4, 1, 'Faulty, please supply details'),
(5, 1, 'Other, please supply details');

-- --------------------------------------------------------

--
-- 表的结构 `oc_return_status`
--

CREATE TABLE `oc_return_status` (
  `return_status_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL DEFAULT '0',
  `name` varchar(32) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_return_status`
--

INSERT INTO `oc_return_status` (`return_status_id`, `language_id`, `name`) VALUES
(1, 1, 'Pending'),
(3, 1, 'Complete'),
(2, 1, 'Awaiting Products');

-- --------------------------------------------------------

--
-- 表的结构 `oc_review`
--

CREATE TABLE `oc_review` (
  `review_id` int(11) NOT NULL,
  `product_id` int(11) NOT NULL,
  `customer_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `author` varchar(64) NOT NULL,
  `text` text NOT NULL,
  `rating` int(1) NOT NULL,
  `rating1` int(1) NOT NULL,
  `rating2` int(1) NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT '0',
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_review`
--

INSERT INTO `oc_review` (`review_id`, `product_id`, `customer_id`, `order_id`, `author`, `text`, `rating`, `rating1`, `rating2`, `status`, `date_added`, `date_modified`) VALUES
(1, 4, 4, 3, 's', '123123123', 5, 5, 5, 1, '2017-05-05 15:03:43', '0000-00-00 00:00:00'),
(2, 4, 4, 2, 's', '12312312速度223123', 7, 6, 9, 1, '2017-05-05 15:04:38', '0000-00-00 00:00:00'),
(3, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 0, '2017-05-05 15:47:44', '0000-00-00 00:00:00'),
(4, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 1, '2017-05-05 15:47:44', '0000-00-00 00:00:00'),
(5, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 1, '2017-05-05 15:47:44', '0000-00-00 00:00:00'),
(6, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 1, '2017-05-05 15:47:44', '0000-00-00 00:00:00'),
(7, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 1, '2017-05-05 15:47:44', '0000-00-00 00:00:00'),
(8, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 1, '2017-05-05 15:47:44', '0000-00-00 00:00:00'),
(9, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 1, '2017-05-05 15:47:44', '0000-00-00 00:00:00'),
(10, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 1, '2017-05-05 15:47:44', '0000-00-00 00:00:00'),
(11, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 1, '2017-05-05 15:47:44', '0000-00-00 00:00:00'),
(12, 4, 4, 1, 's', '123213213s123123', 8, 3, 2, 0, '2017-05-05 15:47:44', '2017-06-02 14:06:19'),
(13, 4, 4, 18, 'Test review auther', 'Fake Review for testing purpose.', 10, 10, 10, 1, '2017-05-26 08:05:53', '2017-06-06 08:23:09'),
(14, 4, 4, 21, '', 'asdf', 5, 5, 5, 0, '2017-05-26 11:04:41', '0000-00-00 00:00:00'),
(15, 4, 4, 31, 'Johnrating', '', 5, 5, 5, 0, '2017-06-05 11:38:06', '0000-00-00 00:00:00'),
(16, 4, 4, 36, 'Johnrating', '', 5, 5, 5, 1, '2017-06-05 14:10:14', '2017-06-06 08:17:54'),
(17, 4, 1, 29, '', '', 5, 5, 5, 0, '2017-06-06 15:53:54', '0000-00-00 00:00:00');

-- --------------------------------------------------------

--
-- 表的结构 `oc_setting`
--

CREATE TABLE `oc_setting` (
  `setting_id` int(11) NOT NULL,
  `store_id` int(11) NOT NULL DEFAULT '0',
  `code` varchar(32) NOT NULL,
  `key` varchar(64) NOT NULL,
  `value` text NOT NULL,
  `serialized` tinyint(1) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_setting`
--

INSERT INTO `oc_setting` (`setting_id`, `store_id`, `code`, `key`, `value`, `serialized`) VALUES
(1, 0, 'shipping', 'shipping_sort_order', '3', 0),
(2, 0, 'sub_total', 'sub_total_sort_order', '1', 0),
(3, 0, 'sub_total', 'sub_total_status', '1', 0),
(4, 0, 'tax', 'tax_status', '1', 0),
(5, 0, 'total', 'total_sort_order', '9', 0),
(6, 0, 'total', 'total_status', '1', 0),
(7, 0, 'tax', 'tax_sort_order', '5', 0),
(8, 0, 'free_checkout', 'free_checkout_sort_order', '1', 0),
(9, 0, 'cod', 'cod_sort_order', '5', 0),
(10, 0, 'cod', 'cod_total', '0.01', 0),
(11, 0, 'cod', 'cod_order_status_id', '1', 0),
(12, 0, 'cod', 'cod_geo_zone_id', '0', 0),
(13, 0, 'cod', 'cod_status', '1', 0),
(14, 0, 'shipping', 'shipping_status', '1', 0),
(15, 0, 'shipping', 'shipping_estimator', '1', 0),
(27, 0, 'coupon', 'coupon_sort_order', '4', 0),
(28, 0, 'coupon', 'coupon_status', '1', 0),
(34, 0, 'flat', 'flat_sort_order', '1', 0),
(35, 0, 'flat', 'flat_status', '1', 0),
(36, 0, 'flat', 'flat_geo_zone_id', '0', 0),
(37, 0, 'flat', 'flat_tax_class_id', '9', 0),
(41, 0, 'flat', 'flat_cost', '5.00', 0),
(42, 0, 'credit', 'credit_sort_order', '7', 0),
(43, 0, 'credit', 'credit_status', '1', 0),
(53, 0, 'reward', 'reward_sort_order', '2', 0),
(54, 0, 'reward', 'reward_status', '1', 0),
(146, 0, 'category', 'category_status', '1', 0),
(158, 0, 'account', 'account_status', '1', 0),
(159, 0, 'affiliate', 'affiliate_status', '1', 0),
(5538, 0, 'pp_standard', 'pp_standard_reversed_status_id', '2', 0),
(5655, 0, 'config', 'config_google_captcha_secret', '', 0),
(5537, 0, 'pp_standard', 'pp_standard_refunded_status_id', '2', 0),
(5656, 0, 'config', 'config_google_captcha_status', '0', 0),
(5654, 0, 'config', 'config_google_captcha_public', '', 0),
(5653, 0, 'config', 'config_google_analytics_status', '0', 0),
(5652, 0, 'config', 'config_google_analytics', '', 0),
(5651, 0, 'config', 'config_error_filename', 'error.log', 0),
(5650, 0, 'config', 'config_error_log', '1', 0),
(5648, 0, 'config', 'config_compression', '0', 0),
(5649, 0, 'config', 'config_error_display', '1', 0),
(5639, 0, 'config', 'config_shared', '0', 0),
(5640, 0, 'config', 'config_robots', 'abot\r\ndbot\r\nebot\r\nhbot\r\nkbot\r\nlbot\r\nmbot\r\nnbot\r\nobot\r\npbot\r\nrbot\r\nsbot\r\ntbot\r\nvbot\r\nybot\r\nzbot\r\nbot.\r\nbot/\r\n_bot\r\n.bot\r\n/bot\r\n-bot\r\n:bot\r\n(bot\r\ncrawl\r\nslurp\r\nspider\r\nseek\r\naccoona\r\nacoon\r\nadressendeutschland\r\nah-ha.com\r\nahoy\r\naltavista\r\nananzi\r\nanthill\r\nappie\r\narachnophilia\r\narale\r\naraneo\r\naranha\r\narchitext\r\naretha\r\narks\r\nasterias\r\natlocal\r\natn\r\natomz\r\naugurfind\r\nbackrub\r\nbannana_bot\r\nbaypup\r\nbdfetch\r\nbig brother\r\nbiglotron\r\nbjaaland\r\nblackwidow\r\nblaiz\r\nblog\r\nblo.\r\nbloodhound\r\nboitho\r\nbooch\r\nbradley\r\nbutterfly\r\ncalif\r\ncassandra\r\nccubee\r\ncfetch\r\ncharlotte\r\nchurl\r\ncienciaficcion\r\ncmc\r\ncollective\r\ncomagent\r\ncombine\r\ncomputingsite\r\ncsci\r\ncurl\r\ncusco\r\ndaumoa\r\ndeepindex\r\ndelorie\r\ndepspid\r\ndeweb\r\ndie blinde kuh\r\ndigger\r\nditto\r\ndmoz\r\ndocomo\r\ndownload express\r\ndtaagent\r\ndwcp\r\nebiness\r\nebingbong\r\ne-collector\r\nejupiter\r\nemacs-w3 search engine\r\nesther\r\nevliya celebi\r\nezresult\r\nfalcon\r\nfelix ide\r\nferret\r\nfetchrover\r\nfido\r\nfindlinks\r\nfireball\r\nfish search\r\nfouineur\r\nfunnelweb\r\ngazz\r\ngcreep\r\ngenieknows\r\ngetterroboplus\r\ngeturl\r\nglx\r\ngoforit\r\ngolem\r\ngrabber\r\ngrapnel\r\ngralon\r\ngriffon\r\ngromit\r\ngrub\r\ngulliver\r\nhamahakki\r\nharvest\r\nhavindex\r\nhelix\r\nheritrix\r\nhku www octopus\r\nhomerweb\r\nhtdig\r\nhtml index\r\nhtml_analyzer\r\nhtmlgobble\r\nhubater\r\nhyper-decontextualizer\r\nia_archiver\r\nibm_planetwide\r\nichiro\r\niconsurf\r\niltrovatore\r\nimage.kapsi.net\r\nimagelock\r\nincywincy\r\nindexer\r\ninfobee\r\ninformant\r\ningrid\r\ninktomisearch.com\r\ninspector web\r\nintelliagent\r\ninternet shinchakubin\r\nip3000\r\niron33\r\nisraeli-search\r\nivia\r\njack\r\njakarta\r\njavabee\r\njetbot\r\njumpstation\r\nkatipo\r\nkdd-explorer\r\nkilroy\r\nknowledge\r\nkototoi\r\nkretrieve\r\nlabelgrabber\r\nlachesis\r\nlarbin\r\nlegs\r\nlibwww\r\nlinkalarm\r\nlink validator\r\nlinkscan\r\nlockon\r\nlwp\r\nlycos\r\nmagpie\r\nmantraagent\r\nmapoftheinternet\r\nmarvin/\r\nmattie\r\nmediafox\r\nmediapartners\r\nmercator\r\nmerzscope\r\nmicrosoft url control\r\nminirank\r\nmiva\r\nmj12\r\nmnogosearch\r\nmoget\r\nmonster\r\nmoose\r\nmotor\r\nmultitext\r\nmuncher\r\nmuscatferret\r\nmwd.search\r\nmyweb\r\nnajdi\r\nnameprotect\r\nnationaldirectory\r\nnazilla\r\nncsa beta\r\nnec-meshexplorer\r\nnederland.zoek\r\nnetcarta webmap engine\r\nnetmechanic\r\nnetresearchserver\r\nnetscoop\r\nnewscan-online\r\nnhse\r\nnokia6682/\r\nnomad\r\nnoyona\r\nnutch\r\nnzexplorer\r\nobjectssearch\r\noccam\r\nomni\r\nopen text\r\nopenfind\r\nopenintelligencedata\r\norb search\r\nosis-project\r\npack rat\r\npageboy\r\npagebull\r\npage_verifier\r\npanscient\r\nparasite\r\npartnersite\r\npatric\r\npear.\r\npegasus\r\nperegrinator\r\npgp key agent\r\nphantom\r\nphpdig\r\npicosearch\r\npiltdownman\r\npimptrain\r\npinpoint\r\npioneer\r\npiranha\r\nplumtreewebaccessor\r\npogodak\r\npoirot\r\npompos\r\npoppelsdorf\r\npoppi\r\npopular iconoclast\r\npsycheclone\r\npublisher\r\npython\r\nrambler\r\nraven search\r\nroach\r\nroad runner\r\nroadhouse\r\nrobbie\r\nrobofox\r\nrobozilla\r\nrules\r\nsalty\r\nsbider\r\nscooter\r\nscoutjet\r\nscrubby\r\nsearch.\r\nsearchprocess\r\nsemanticdiscovery\r\nsenrigan\r\nsg-scout\r\nshai\'hulud\r\nshark\r\nshopwiki\r\nsidewinder\r\nsift\r\nsilk\r\nsimmany\r\nsite searcher\r\nsite valet\r\nsitetech-rover\r\nskymob.com\r\nsleek\r\nsmartwit\r\nsna-\r\nsnappy\r\nsnooper\r\nsohu\r\nspeedfind\r\nsphere\r\nsphider\r\nspinner\r\nspyder\r\nsteeler/\r\nsuke\r\nsuntek\r\nsupersnooper\r\nsurfnomore\r\nsven\r\nsygol\r\nszukacz\r\ntach black widow\r\ntarantula\r\ntempleton\r\n/teoma\r\nt-h-u-n-d-e-r-s-t-o-n-e\r\ntheophrastus\r\ntitan\r\ntitin\r\ntkwww\r\ntoutatis\r\nt-rex\r\ntutorgig\r\ntwiceler\r\ntwisted\r\nucsd\r\nudmsearch\r\nurl check\r\nupdated\r\nvagabondo\r\nvalkyrie\r\nverticrawl\r\nvictoria\r\nvision-search\r\nvolcano\r\nvoyager/\r\nvoyager-hc\r\nw3c_validator\r\nw3m2\r\nw3mir\r\nwalker\r\nwallpaper\r\nwanderer\r\nwauuu\r\nwavefire\r\nweb core\r\nweb hopper\r\nweb wombat\r\nwebbandit\r\nwebcatcher\r\nwebcopy\r\nwebfoot\r\nweblayers\r\nweblinker\r\nweblog monitor\r\nwebmirror\r\nwebmonkey\r\nwebquest\r\nwebreaper\r\nwebsitepulse\r\nwebsnarf\r\nwebstolperer\r\nwebvac\r\nwebwalk\r\nwebwatch\r\nwebwombat\r\nwebzinger\r\nwhizbang\r\nwhowhere\r\nwild ferret\r\nworldlight\r\nwwwc\r\nwwwster\r\nxenu\r\nxget\r\nxift\r\nxirq\r\nyandex\r\nyanga\r\nyeti\r\nyodao\r\nzao\r\nzippp\r\nzyborg', 0),
(5645, 0, 'config', 'config_maintenance', '0', 0),
(5646, 0, 'config', 'config_password', '1', 0),
(5647, 0, 'config', 'config_encryption', '404ccc2699da4381c0f685c7a354bacb', 0),
(5644, 0, 'config', 'config_file_mime_allowed', 'text/plain\r\nimage/png\r\nimage/jpeg\r\nimage/gif\r\nimage/bmp\r\nimage/tiff\r\nimage/svg+xml\r\napplication/zip\r\n&quot;application/zip&quot;\r\napplication/x-zip\r\n&quot;application/x-zip&quot;\r\napplication/x-zip-compressed\r\n&quot;application/x-zip-compressed&quot;\r\napplication/rar\r\n&quot;application/rar&quot;\r\napplication/x-rar\r\n&quot;application/x-rar&quot;\r\napplication/x-rar-compressed\r\n&quot;application/x-rar-compressed&quot;\r\napplication/octet-stream\r\n&quot;application/octet-stream&quot;\r\naudio/mpeg\r\nvideo/quicktime\r\napplication/pdf', 0),
(5641, 0, 'config', 'config_seo_url', '0', 0),
(5642, 0, 'config', 'config_file_max_size', '300000', 0),
(5643, 0, 'config', 'config_file_ext_allowed', 'zip\r\ntxt\r\npng\r\njpe\r\njpeg\r\njpg\r\ngif\r\nbmp\r\nico\r\ntiff\r\ntif\r\nsvg\r\nsvgz\r\nzip\r\nrar\r\nmsi\r\ncab\r\nmp3\r\nqt\r\nmov\r\npdf\r\npsd\r\nai\r\neps\r\nps\r\ndoc', 0),
(5536, 0, 'pp_standard', 'pp_standard_processed_status_id', '2', 0),
(94, 0, 'voucher', 'voucher_sort_order', '8', 0),
(95, 0, 'voucher', 'voucher_status', '1', 0),
(103, 0, 'free_checkout', 'free_checkout_status', '1', 0),
(104, 0, 'free_checkout', 'free_checkout_order_status_id', '1', 0),
(5638, 0, 'config', 'config_secure', '0', 0),
(5637, 0, 'config', 'config_mail_alert', '', 0),
(5636, 0, 'config', 'config_mail_smtp_timeout', '5', 0),
(5635, 0, 'config', 'config_mail_smtp_port', '26', 0),
(5633, 0, 'config', 'config_mail_smtp_username', 'ogden@aupos.com.au', 0),
(5634, 0, 'config', 'config_mail_smtp_password', 'aupos2016', 0),
(5632, 0, 'config', 'config_mail_smtp_hostname', 'mail.aupos.com.au', 0),
(5631, 0, 'config', 'config_mail_parameter', 'ogden@aupos.com.au', 0),
(5630, 0, 'config', 'config_mail_protocol', 'smtp', 0),
(5629, 0, 'config', 'config_ftp_status', '0', 0),
(5628, 0, 'config', 'config_ftp_root', '', 0),
(5627, 0, 'config', 'config_ftp_password', '', 0),
(5626, 0, 'config', 'config_ftp_username', '', 0),
(5625, 0, 'config', 'config_ftp_port', '21', 0),
(5624, 0, 'config', 'config_ftp_hostname', 'mk.l.onebound.cn', 0),
(5623, 0, 'config', 'config_image_location_height', '120', 0),
(5622, 0, 'config', 'config_image_location_width', '120', 0),
(5621, 0, 'config', 'config_image_cart_height', '47', 0),
(5620, 0, 'config', 'config_image_cart_width', '47', 0),
(5619, 0, 'config', 'config_image_wishlist_height', '47', 0),
(5618, 0, 'config', 'config_image_wishlist_width', '47', 0),
(5617, 0, 'config', 'config_image_compare_height', '90', 0),
(5616, 0, 'config', 'config_image_compare_width', '90', 0),
(5615, 0, 'config', 'config_image_related_height', '80', 0),
(5614, 0, 'config', 'config_image_related_width', '80', 0),
(5613, 0, 'config', 'config_image_additional_height', '74', 0),
(5612, 0, 'config', 'config_image_additional_width', '74', 0),
(5611, 0, 'config', 'config_image_product_height', '228', 0),
(5610, 0, 'config', 'config_image_product_width', '228', 0),
(5609, 0, 'config', 'config_image_popup_height', '500', 0),
(5608, 0, 'config', 'config_image_popup_width', '500', 0),
(5607, 0, 'config', 'config_image_thumb_height', '228', 0),
(5606, 0, 'config', 'config_image_thumb_width', '228', 0),
(5605, 0, 'config', 'config_image_category_height', '80', 0),
(5604, 0, 'config', 'config_image_category_width', '80', 0),
(5603, 0, 'config', 'config_icon', 'catalog/cart.png', 0),
(5602, 0, 'config', 'config_logo', 'catalog/logo.png', 0),
(5601, 0, 'config', 'config_return_status_id', '2', 0),
(5600, 0, 'config', 'config_return_id', '0', 0),
(5599, 0, 'config', 'config_affiliate_mail', '0', 0),
(5598, 0, 'config', 'config_affiliate_id', '4', 0),
(5597, 0, 'config', 'config_affiliate_commission', '5', 0),
(5596, 0, 'config', 'config_affiliate_auto', '0', 0),
(5595, 0, 'config', 'config_affiliate_approval', '0', 0),
(5594, 0, 'config', 'config_stock_checkout', '0', 0),
(5593, 0, 'config', 'config_stock_warning', '0', 0),
(5592, 0, 'config', 'config_stock_display', '0', 0),
(5591, 0, 'config', 'config_order_mail', '0', 0),
(5590, 0, 'config', 'config_complete_status', 'a:1:{i:0;s:1:\"5\";}', 1),
(5588, 0, 'config', 'config_order_status_id', '1', 0),
(5589, 0, 'config', 'config_processing_status', 'a:2:{i:0;s:1:\"2\";i:1;s:1:\"1\";}', 1),
(5587, 0, 'config', 'config_checkout_id', '5', 0),
(5586, 0, 'config', 'config_checkout_guest', '1', 0),
(5584, 0, 'config', 'config_api_id', '1', 0),
(5585, 0, 'config', 'config_cart_weight', '1', 0),
(5583, 0, 'config', 'config_invoice_prefix', 'INV-2013-00', 0),
(5579, 0, 'config', 'config_customer_price', '0', 0),
(5580, 0, 'config', 'config_login_attempts', '5', 0),
(5581, 0, 'config', 'config_account_id', '3', 0),
(5582, 0, 'config', 'config_account_mail', '0', 0),
(5578, 0, 'config', 'config_customer_group_display', 'a:1:{i:0;s:1:\"1\";}', 1),
(5577, 0, 'config', 'config_customer_group_id', '1', 0),
(5576, 0, 'config', 'config_customer_online', '0', 0),
(5575, 0, 'config', 'config_tax_customer', 'shipping', 0),
(5574, 0, 'config', 'config_tax_default', 'shipping', 0),
(5573, 0, 'config', 'config_tax', '1', 0),
(5572, 0, 'config', 'config_voucher_max', '1000', 0),
(5571, 0, 'config', 'config_voucher_min', '1', 0),
(5570, 0, 'config', 'config_review_mail', '0', 0),
(5569, 0, 'config', 'config_review_guest', '1', 0),
(5568, 0, 'config', 'config_review_status', '1', 0),
(5567, 0, 'config', 'config_limit_admin', '20', 0),
(5566, 0, 'config', 'config_product_description_length', '100', 0),
(5565, 0, 'config', 'config_product_limit', '20', 0),
(5563, 0, 'config', 'config_weight_class_id', '1', 0),
(5564, 0, 'config', 'config_product_count', '1', 0),
(5562, 0, 'config', 'config_length_class_id', '1', 0),
(5561, 0, 'config', 'config_currency_auto', '1', 0),
(5560, 0, 'config', 'config_currency', 'AUD', 0),
(5559, 0, 'config', 'config_admin_language', 'en', 0),
(5558, 0, 'config', 'config_language', 'en', 0),
(5557, 0, 'config', 'config_zone_id', '0', 0),
(5556, 0, 'config', 'config_country_id', '1', 0),
(5551, 0, 'config', 'config_meta_title', 'Monkey King Thai Restaurant', 0),
(5552, 0, 'config', 'config_meta_description', '', 0),
(5553, 0, 'config', 'config_meta_keyword', '', 0),
(5554, 0, 'config', 'config_template', 'menulog', 0),
(5555, 0, 'config', 'config_layout_id', '4', 0),
(5550, 0, 'config', 'config_location', 'a:1:{i:0;s:1:\"4\";}', 1),
(5549, 0, 'config', 'config_comment', '', 0),
(5548, 0, 'config', 'config_open', '', 0),
(5544, 0, 'config', 'config_email', 'sales@monkeyking.com.au', 0),
(5547, 0, 'config', 'config_image', '', 0),
(5546, 0, 'config', 'config_fax', '', 0),
(5545, 0, 'config', 'config_telephone', '(02) 9416 9301', 0),
(5534, 0, 'pp_standard', 'pp_standard_failed_status_id', '2', 0),
(5535, 0, 'pp_standard', 'pp_standard_pending_status_id', '1', 0),
(5533, 0, 'pp_standard', 'pp_standard_expired_status_id', '2', 0),
(5532, 0, 'pp_standard', 'pp_standard_denied_status_id', '2', 0),
(5531, 0, 'pp_standard', 'pp_standard_completed_status_id', '2', 0),
(5529, 0, 'pp_standard', 'pp_standard_status', '1', 0),
(5530, 0, 'pp_standard', 'pp_standard_canceled_reversal_status_id', '2', 0),
(5528, 0, 'pp_standard', 'pp_standard_geo_zone_id', '0', 0),
(5527, 0, 'pp_standard', 'pp_standard_sort_order', '', 0),
(5526, 0, 'pp_standard', 'pp_standard_total', '', 0),
(5525, 0, 'pp_standard', 'pp_standard_transaction', '0', 0),
(5524, 0, 'pp_standard', 'pp_standard_debug', '1', 0),
(5523, 0, 'pp_standard', 'pp_standard_test', '1', 0),
(5542, 0, 'config', 'config_address', '338 Pacific highway, Lindfield NSW 2070', 0),
(5543, 0, 'config', 'config_geocode', '', 0),
(5541, 0, 'config', 'config_owner', 'Store Owner', 0),
(5540, 0, 'config', 'config_name', 'Monkey King Thai Restaurant', 0),
(5522, 0, 'pp_standard', 'pp_standard_email', 'lxq73061-facilitator@qq.com', 0),
(5539, 0, 'pp_standard', 'pp_standard_voided_status_id', '2', 0),
(5657, 0, 'low_order_fee', 'low_order_fee_total', '', 0),
(5658, 0, 'low_order_fee', 'low_order_fee_fee', '', 0),
(5659, 0, 'low_order_fee', 'low_order_fee_tax_class_id', '0', 0),
(5660, 0, 'low_order_fee', 'low_order_fee_status', '1', 0),
(5661, 0, 'low_order_fee', 'low_order_fee_sort_order', '8', 0);

-- --------------------------------------------------------

--
-- 表的结构 `oc_shop_coupon`
--

CREATE TABLE `oc_shop_coupon` (
  `shop_coupon_id` int(11) UNSIGNED NOT NULL,
  `name` varchar(128) NOT NULL,
  `type` tinyint(1) NOT NULL,
  `discount` decimal(15,4) NOT NULL,
  `times` int(11) NOT NULL DEFAULT '0',
  `total` decimal(15,4) NOT NULL,
  `max_amount` decimal(10,4) NOT NULL,
  `coupon_product_ids` varchar(25) NOT NULL,
  `date_start` date NOT NULL,
  `date_end` date NOT NULL,
  `status` tinyint(1) NOT NULL,
  `info` text NOT NULL,
  `sort_order` int(3) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8 ROW_FORMAT=COMPACT;

--
-- 转存表中的数据 `oc_shop_coupon`
--

INSERT INTO `oc_shop_coupon` (`shop_coupon_id`, `name`, `type`, `discount`, `times`, `total`, `max_amount`, `coupon_product_ids`, `date_start`, `date_end`, `status`, `info`, `sort_order`, `date_added`) VALUES
(11, '10% OFF YOUR 1ST ORDER', 1, '10.0000', 1, '0.0000', '0.0000', '', '2017-06-06', '2018-06-06', 1, 'Not available with other offers or meal deals.', 1, '2017-06-06 14:00:36'),
(7, 'ORDER 8 TIMES 9TH IS FREE', 3, '12.5000', 8, '0.0000', '0.0000', '', '2017-06-06', '2018-06-06', 1, 'Not available with other offers. Delivery fee excluded. Loyalty discount is tracked only once a day(user must login before order is submitted). Your loyalty discount is limited to the average order value of your past loyalty orders.', 2, '2017-04-11 09:17:06'),
(8, 'Bonus FREE 1 x BONUS Free Prawn Chips', 2, '0.0000', 0, '50.0000', '75.0000', '1', '2017-06-06', '2018-06-06', 1, 'Order between $50 and $75 for Free Prawn Chips.\r\n\r\nNot available with other offers. ', 3, '2017-04-11 09:18:16'),
(9, 'Bonus FREE 1 x BONUS Free Seafood Salad or Prawn Chips', 2, '0.0000', 0, '75.0000', '100.0000', '2,1', '2017-06-06', '2018-06-06', 1, 'Order between $75 and $100 for Free Seafood Salad.\r\n\r\nNot available with other offers. ', 4, '2017-05-26 11:18:56'),
(10, 'Bonus FREE 1 x BONUS Free Garlic Bread', 2, '0.0000', 0, '100.0000', '0.0000', '3', '2017-06-06', '2018-06-06', 1, 'Order $100 or more for Free Garlic Bread.\r\n\r\nNot available with other offers. ', 5, '2017-05-26 11:19:10');

-- --------------------------------------------------------

--
-- 表的结构 `oc_shop_coupon_product`
--

CREATE TABLE `oc_shop_coupon_product` (
  `product_id` int(11) UNSIGNED NOT NULL,
  `name` varchar(128) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_shop_coupon_product`
--

INSERT INTO `oc_shop_coupon_product` (`product_id`, `name`, `date_added`) VALUES
(1, 'Prawn Chips', '2017-05-19 15:56:00'),
(2, 'Seafood Salad', '2017-05-26 14:35:43'),
(3, 'Garlic Bread', '2017-05-26 14:36:04');

-- --------------------------------------------------------

--
-- 表的结构 `oc_shop_image`
--

CREATE TABLE `oc_shop_image` (
  `shop_image_id` int(11) NOT NULL,
  `location_id` int(11) NOT NULL,
  `image` varchar(255) DEFAULT NULL,
  `sort_order` int(3) NOT NULL DEFAULT '0'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_shop_info`
--

CREATE TABLE `oc_shop_info` (
  `shop_info_id` int(11) UNSIGNED NOT NULL,
  `location_id` int(11) NOT NULL,
  `info` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_shop_info`
--

INSERT INTO `oc_shop_info` (`shop_info_id`, `location_id`, `info`) VALUES
(175, 4, 'Note: “OPEN 7 Days!!!“'),
(176, 4, 'Order now for later when restaurant opens.');

-- --------------------------------------------------------

--
-- 表的结构 `oc_shop_tag`
--

CREATE TABLE `oc_shop_tag` (
  `tag_id` int(11) UNSIGNED NOT NULL COMMENT '标签id',
  `name` varchar(32) NOT NULL COMMENT '标签名称',
  `sort` int(11) UNSIGNED NOT NULL DEFAULT '0' COMMENT '标签排序',
  `addtime` datetime NOT NULL COMMENT '添加时间',
  `status` tinyint(1) NOT NULL DEFAULT '1' COMMENT '状态'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_shop_tag`
--

INSERT INTO `oc_shop_tag` (`tag_id`, `name`, `sort`, `addtime`, `status`) VALUES
(4, 'Thai', 2, '2017-03-21 19:47:41', 1),
(8, 'Asian', 1, '2017-03-22 10:47:22', 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_shop_time`
--

CREATE TABLE `oc_shop_time` (
  `shop_time_id` int(11) UNSIGNED NOT NULL COMMENT '时间表id',
  `location_id` int(11) NOT NULL COMMENT '店铺id',
  `times` text NOT NULL,
  `unavailable` text NOT NULL,
  `pretime` varchar(225) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_shop_time`
--

INSERT INTO `oc_shop_time` (`shop_time_id`, `location_id`, `times`, `unavailable`, `pretime`) VALUES
(1, 1, '2018-12-12', '', ''),
(116, 1, '2018-12-15', '', ''),
(117, 2, '2018-12-11', '', ''),
(118, 2, '2018-12-14', '', '');

-- --------------------------------------------------------

--
-- 表的结构 `oc_state`
--

CREATE TABLE `oc_state` (
  `state_id` int(11) UNSIGNED NOT NULL,
  `country_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT '1'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_state`
--

INSERT INTO `oc_state` (`state_id`, `country_id`, `name`, `status`) VALUES
(2, 1, 'New South Wales', 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_stock_status`
--

CREATE TABLE `oc_stock_status` (
  `stock_status_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(32) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_stock_status`
--

INSERT INTO `oc_stock_status` (`stock_status_id`, `language_id`, `name`) VALUES
(7, 1, 'In Stock'),
(8, 1, 'Pre-Order'),
(5, 1, 'Out Of Stock'),
(6, 1, '2-3 Days');

-- --------------------------------------------------------

--
-- 表的结构 `oc_store`
--

CREATE TABLE `oc_store` (
  `store_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL,
  `url` varchar(255) NOT NULL,
  `ssl` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_suburb`
--

CREATE TABLE `oc_suburb` (
  `suburb_id` int(11) UNSIGNED NOT NULL,
  `country_id` int(11) NOT NULL,
  `state_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT '1'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_suburb`
--

INSERT INTO `oc_suburb` (`suburb_id`, `country_id`, `state_id`, `name`, `status`) VALUES
(2, 1, 2, 'Chatswood West', 1),
(3, 1, 2, 'Killara', 1),
(4, 1, 2, 'Chatswood', 1),
(5, 1, 2, 'Roseville', 1),
(6, 1, 2, 'East Lindfield', 1),
(7, 1, 2, 'Lindfield', 1),
(8, 1, 2, 'East Killara', 1),
(9, 1, 2, 'Gordon', 1),
(10, 1, 2, 'Roseville Chase', 1),
(11, 1, 2, 'West Pymble', 1),
(12, 1, 2, 'Lindfield West', 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_table_link`
--

CREATE TABLE `oc_table_link` (
  `link_id` int(10) UNSIGNED NOT NULL,
  `table_link` varchar(300) NOT NULL,
  `site_id` int(11) NOT NULL,
  `table_code` varchar(128) NOT NULL,
  `pos_saleId` int(11) NOT NULL,
  `status` tinyint(1) DEFAULT '0',
  `link_generate_time` datetime NOT NULL,
  `add_time` datetime DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_table_link`
--

INSERT INTO `oc_table_link` (`link_id`, `table_link`, `site_id`, `table_code`, `pos_saleId`, `status`, `link_generate_time`, `add_time`) VALUES
(1, '17 1 VIP-2 20180102030405', 0, 'VIP-2', 1, 0, '2018-01-24 00:00:00', NULL),
(2, '17 1 01 20180102030405', 1, '01', 2, 0, '2018-01-24 01:00:00', NULL),
(3, '19 1 02 20180102030406', 1, '02', 19, 0, '2018-01-25 00:00:00', NULL);

-- --------------------------------------------------------

--
-- 表的结构 `oc_table_linksub`
--

CREATE TABLE `oc_table_linksub` (
  `link_id` int(11) NOT NULL,
  `linksub_id` int(10) UNSIGNED NOT NULL,
  `downloaded` tinyint(1) DEFAULT '0',
  `order_id` int(11) DEFAULT '-1',
  `sub_status` tinyint(1) DEFAULT '0',
  `client_browser` varchar(500) DEFAULT '',
  `client_ip` varchar(50) DEFAULT '',
  `order_items_qrcode_string` varchar(5000) DEFAULT '',
  `sub_add_time` datetime DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_table_linksub`
--

INSERT INTO `oc_table_linksub` (`link_id`, `linksub_id`, `downloaded`, `order_id`, `sub_status`, `client_browser`, `client_ip`, `order_items_qrcode_string`, `sub_add_time`) VALUES
(1, 1, 1, 138, 10, '', '192.168.1.220', '', NULL),
(2, 1, 1, 17, 10, '', '192.168.1.220', '', NULL),
(3, 1, 1, 19, 10, '', '192.168.1.220', '', NULL);

-- --------------------------------------------------------

--
-- 表的结构 `oc_tax_class`
--

CREATE TABLE `oc_tax_class` (
  `tax_class_id` int(11) NOT NULL,
  `title` varchar(32) NOT NULL,
  `description` varchar(255) NOT NULL,
  `approve` tinyint(1) NOT NULL DEFAULT '0',
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_tax_class`
--

INSERT INTO `oc_tax_class` (`tax_class_id`, `title`, `description`, `approve`, `date_added`, `date_modified`) VALUES
(12, 'FRE', 'GST free', 0, '2017-06-27 11:46:56', '2017-06-27 11:47:14'),
(11, 'GST', 'Goods And Services Tax', 1, '2017-05-30 08:52:14', '2017-07-20 08:34:14');

-- --------------------------------------------------------

--
-- 表的结构 `oc_tax_rate`
--

CREATE TABLE `oc_tax_rate` (
  `tax_rate_id` int(11) NOT NULL,
  `geo_zone_id` int(11) NOT NULL DEFAULT '0',
  `name` varchar(32) NOT NULL,
  `rate` decimal(15,4) NOT NULL DEFAULT '0.0000',
  `type` char(1) NOT NULL,
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_tax_rate`
--

INSERT INTO `oc_tax_rate` (`tax_rate_id`, `geo_zone_id`, `name`, `rate`, `type`, `date_added`, `date_modified`) VALUES
(89, 1, 'FRE', '0.0000', 'P', '2017-06-27 11:49:37', '2017-07-03 10:25:56'),
(88, 1, 'GST', '10.0000', 'P', '2017-05-30 08:52:45', '2017-06-27 11:49:44');

-- --------------------------------------------------------

--
-- 表的结构 `oc_tax_rate_to_customer_group`
--

CREATE TABLE `oc_tax_rate_to_customer_group` (
  `tax_rate_id` int(11) NOT NULL,
  `customer_group_id` int(11) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_tax_rate_to_customer_group`
--

INSERT INTO `oc_tax_rate_to_customer_group` (`tax_rate_id`, `customer_group_id`) VALUES
(88, 1);

-- --------------------------------------------------------

--
-- 表的结构 `oc_tax_rule`
--

CREATE TABLE `oc_tax_rule` (
  `tax_rule_id` int(11) NOT NULL,
  `tax_class_id` int(11) NOT NULL,
  `tax_rate_id` int(11) NOT NULL,
  `based` varchar(10) NOT NULL,
  `priority` int(5) NOT NULL DEFAULT '1'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_upload`
--

CREATE TABLE `oc_upload` (
  `upload_id` int(11) NOT NULL,
  `name` varchar(255) NOT NULL,
  `filename` varchar(255) NOT NULL,
  `code` varchar(255) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_upload`
--

INSERT INTO `oc_upload` (`upload_id`, `name`, `filename`, `code`, `date_added`) VALUES
(1, '1.jpg', '1.jpg.cfc9a2b5320fb782ab9caab2e1ba7a8d', '5f4b96edb0a2feae88b1ab1896f406e4fb5db8cc', '2017-05-05 16:24:07'),
(2, '541169c816a71.jpg', '541169c816a71.jpg.965234384db46a99ef4d341142bfc9dd', 'fa10c13133607059bbe5a323d47502c132cbbcd7', '2017-05-11 10:54:50'),
(3, 'printer.bmp', 'printer.bmp.35ebcb18e3cc84d046db12b9a63dc55e', '27db3e65e5364ad389fd0777cd0d5a26d83cbb49', '2017-05-26 12:21:13');

-- --------------------------------------------------------

--
-- 表的结构 `oc_url_alias`
--

CREATE TABLE `oc_url_alias` (
  `url_alias_id` int(11) NOT NULL,
  `query` varchar(255) NOT NULL,
  `keyword` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_url_alias`
--

INSERT INTO `oc_url_alias` (`url_alias_id`, `query`, `keyword`) VALUES
(772, 'information_id=4', 'about_us'),
(925, 'product_id=95', ''),
(828, 'manufacturer_id=9', 'canon'),
(846, 'manufacturer_id=5', 'htc'),
(830, 'manufacturer_id=7', 'hewlett-packard'),
(831, 'manufacturer_id=6', 'palm'),
(832, 'manufacturer_id=10', 'sony'),
(841, 'information_id=6', 'delivery'),
(842, 'information_id=3', 'privacy'),
(843, 'information_id=5', 'terms'),
(927, 'product_id=97', ''),
(928, 'product_id=98', ''),
(929, 'product_id=99', ''),
(930, 'product_id=100', ''),
(931, 'product_id=101', ''),
(932, 'product_id=102', ''),
(933, 'product_id=103', ''),
(934, 'product_id=104', ''),
(935, 'product_id=105', ''),
(937, 'product_id=107', ''),
(938, 'product_id=108', ''),
(939, 'product_id=109', ''),
(940, 'product_id=110', ''),
(942, 'product_id=112', ''),
(943, 'product_id=113', '');

-- --------------------------------------------------------

--
-- 表的结构 `oc_user`
--

CREATE TABLE `oc_user` (
  `id` int(11) NOT NULL,
  `user_group_id` int(11) NOT NULL DEFAULT '0',
  `username` varchar(20) DEFAULT NULL,
  `name` varchar(255) NOT NULL,
  `password` varchar(255) NOT NULL,
  `auth_token` mediumtext NOT NULL,
  `salt` varchar(9) DEFAULT NULL,
  `firstname` varchar(32) DEFAULT NULL,
  `lastname` varchar(32) DEFAULT NULL,
  `email` varchar(96) DEFAULT NULL,
  `image` varchar(255) DEFAULT NULL,
  `code` varchar(40) DEFAULT NULL,
  `ip` varchar(40) DEFAULT NULL,
  `status` tinyint(1) DEFAULT NULL,
  `date_added` datetime DEFAULT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_user`
--

INSERT INTO `oc_user` (`id`, `user_group_id`, `username`, `name`, `password`, `auth_token`, `salt`, `firstname`, `lastname`, `email`, `image`, `code`, `ip`, `status`, `date_added`) VALUES
(1, 1, 'admin', '', '0220cc6b3973b88e7c8c7ea92141bfe021b2a66c', '', 'e68e40456', 'John', 'Doe', 'grantedwins5@hotmail.com', '', '', '192.168.1.220', 1, '2017-03-17 11:52:03'),
(2, 1, 'Owner', '', '0f03127303e4b9164ff29224b4c21278d471a337', '', '285fc0403', 'David', 'Smith', 'grantedwins@gmail.com', '', '', '', 1, '2017-07-06 10:22:44'),
(6, 0, NULL, 'test2 user', '$2y$10$GOBy15wdnafx45BYCuSNIul17W6jHdrti7m7omvyxgBQXjK56U0/.', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0L2dyb3VwYnV5L3B1YmxpYy9hcGkvdXNlci9sb2dpbiIsImlhdCI6MTU0Mzg5MzU4OCwiZXhwIjoxNTQzODk3MTg4LCJuYmYiOjE1NDM4OTM1ODgsImp0aSI6IlB4WkR5QUVCdDZ0bDRKbFMiLCJzdWIiOjYsInBydiI6Ijg3ZTBhZjFlZjlmZDE1ODEyZmRlYzk3MTUzYTE0ZTBiMDQ3NTQ2YWEifQ.WupJG15_U4QBEWcMX1liK71bXOrGyrjsBFuSGehB-j4', NULL, NULL, NULL, 'qidizn@gmail.com', NULL, NULL, NULL, NULL, NULL),
(8, 0, NULL, 'roben', '$2y$10$m7Cy0xanP462mVvKMNbnJuDnNN06WZJZtmBJr1LtvU6tqc3II9W.K', 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJodHRwOi8vbG9jYWxob3N0L2dyb3VwYnV5L3B1YmxpYy9hcGkvdXNlci9sb2dpbiIsImlhdCI6MTU0Mzg5Nzc1MywiZXhwIjoxNTQzOTAxMzUzLCJuYmYiOjE1NDM4OTc3NTMsImp0aSI6ImRLdjJ2bHlaSW55WDlzNGIiLCJzdWIiOjgsInBydiI6Ijg3ZTBhZjFlZjlmZDE1ODEyZmRlYzk3MTUzYTE0ZTBiMDQ3NTQ2YWEifQ.hPDkuNi1BlZglN9rUJvH2xcd7EjybZE47T3jQURYjnM', NULL, NULL, NULL, 'roben@123.com', NULL, NULL, NULL, NULL, NULL);

-- --------------------------------------------------------

--
-- 表的结构 `oc_user_group`
--

CREATE TABLE `oc_user_group` (
  `user_group_id` int(11) NOT NULL,
  `name` varchar(64) NOT NULL,
  `permission` text NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_user_group`
--

INSERT INTO `oc_user_group` (`user_group_id`, `name`, `permission`) VALUES
(1, 'Administrator', 'a:2:{s:6:\"access\";a:191:{i:0;s:16:\"catalog/add_type\";i:1;s:17:\"catalog/attribute\";i:2;s:23:\"catalog/attribute_group\";i:3;s:16:\"catalog/category\";i:4;s:16:\"catalog/download\";i:5;s:14:\"catalog/filter\";i:6;s:19:\"catalog/information\";i:7;s:20:\"catalog/manufacturer\";i:8;s:14:\"catalog/option\";i:9;s:15:\"catalog/product\";i:10;s:19:\"catalog/product_tag\";i:11;s:17:\"catalog/recurring\";i:12;s:14:\"catalog/review\";i:13;s:11:\"catalog/tag\";i:14;s:18:\"common/column_left\";i:15;s:18:\"common/filemanager\";i:16;s:11:\"common/menu\";i:17;s:14:\"common/profile\";i:18;s:12:\"common/stats\";i:19;s:13:\"design/banner\";i:20;s:13:\"design/layout\";i:21;s:14:\"extension/feed\";i:22;s:15:\"extension/fraud\";i:23;s:19:\"extension/installer\";i:24;s:22:\"extension/modification\";i:25;s:16:\"extension/module\";i:26;s:17:\"extension/openbay\";i:27;s:17:\"extension/payment\";i:28;s:18:\"extension/shipping\";i:29;s:15:\"extension/total\";i:30;s:16:\"feed/google_base\";i:31;s:19:\"feed/google_sitemap\";i:32;s:15:\"feed/openbaypro\";i:33;s:18:\"fraud/fraudlabspro\";i:34;s:13:\"fraud/maxmind\";i:35;s:20:\"localisation/country\";i:36;s:19:\"localisation/coupon\";i:37;s:21:\"localisation/currency\";i:38;s:21:\"localisation/geo_zone\";i:39;s:21:\"localisation/language\";i:40;s:25:\"localisation/length_class\";i:41;s:21:\"localisation/location\";i:42;s:25:\"localisation/order_status\";i:43;s:20:\"localisation/product\";i:44;s:26:\"localisation/return_action\";i:45;s:26:\"localisation/return_reason\";i:46;s:26:\"localisation/return_status\";i:47;s:19:\"localisation/review\";i:48;s:18:\"localisation/state\";i:49;s:25:\"localisation/stock_status\";i:50;s:19:\"localisation/suburb\";i:51;s:22:\"localisation/tax_class\";i:52;s:21:\"localisation/tax_rate\";i:53;s:25:\"localisation/weight_class\";i:54;s:17:\"localisation/zone\";i:55;s:19:\"marketing/affiliate\";i:56;s:17:\"marketing/contact\";i:57;s:16:\"marketing/coupon\";i:58;s:19:\"marketing/marketing\";i:59;s:14:\"module/account\";i:60;s:16:\"module/affiliate\";i:61;s:20:\"module/amazon_button\";i:62;s:19:\"module/amazon_login\";i:63;s:17:\"module/amazon_pay\";i:64;s:13:\"module/banner\";i:65;s:17:\"module/bestseller\";i:66;s:15:\"module/carousel\";i:67;s:15:\"module/category\";i:68;s:19:\"module/ebay_listing\";i:69;s:15:\"module/featured\";i:70;s:13:\"module/filter\";i:71;s:22:\"module/google_hangouts\";i:72;s:11:\"module/html\";i:73;s:18:\"module/information\";i:74;s:13:\"module/latest\";i:75;s:16:\"module/pp_button\";i:76;s:15:\"module/pp_login\";i:77;s:16:\"module/slideshow\";i:78;s:14:\"module/special\";i:79;s:12:\"module/store\";i:80;s:14:\"openbay/amazon\";i:81;s:22:\"openbay/amazon_listing\";i:82;s:22:\"openbay/amazon_product\";i:83;s:16:\"openbay/amazonus\";i:84;s:24:\"openbay/amazonus_listing\";i:85;s:24:\"openbay/amazonus_product\";i:86;s:12:\"openbay/ebay\";i:87;s:20:\"openbay/ebay_profile\";i:88;s:21:\"openbay/ebay_template\";i:89;s:12:\"openbay/etsy\";i:90;s:20:\"openbay/etsy_product\";i:91;s:21:\"openbay/etsy_shipping\";i:92;s:17:\"openbay/etsy_shop\";i:93;s:23:\"payment/amazon_checkout\";i:94;s:24:\"payment/amazon_login_pay\";i:95;s:24:\"payment/authorizenet_aim\";i:96;s:24:\"payment/authorizenet_sim\";i:97;s:21:\"payment/bank_transfer\";i:98;s:22:\"payment/bluepay_hosted\";i:99;s:24:\"payment/bluepay_redirect\";i:100;s:14:\"payment/cheque\";i:101;s:11:\"payment/cod\";i:102;s:17:\"payment/firstdata\";i:103;s:24:\"payment/firstdata_remote\";i:104;s:21:\"payment/free_checkout\";i:105;s:14:\"payment/g2apay\";i:106;s:17:\"payment/globalpay\";i:107;s:24:\"payment/globalpay_remote\";i:108;s:22:\"payment/klarna_account\";i:109;s:22:\"payment/klarna_invoice\";i:110;s:14:\"payment/liqpay\";i:111;s:14:\"payment/nochex\";i:112;s:15:\"payment/paymate\";i:113;s:16:\"payment/paypoint\";i:114;s:13:\"payment/payza\";i:115;s:26:\"payment/perpetual_payments\";i:116;s:18:\"payment/pp_express\";i:117;s:18:\"payment/pp_payflow\";i:118;s:25:\"payment/pp_payflow_iframe\";i:119;s:14:\"payment/pp_pro\";i:120;s:21:\"payment/pp_pro_iframe\";i:121;s:19:\"payment/pp_standard\";i:122;s:14:\"payment/realex\";i:123;s:21:\"payment/realex_remote\";i:124;s:22:\"payment/sagepay_direct\";i:125;s:22:\"payment/sagepay_server\";i:126;s:18:\"payment/sagepay_us\";i:127;s:24:\"payment/securetrading_pp\";i:128;s:24:\"payment/securetrading_ws\";i:129;s:14:\"payment/skrill\";i:130;s:19:\"payment/twocheckout\";i:131;s:28:\"payment/web_payment_software\";i:132;s:16:\"payment/worldpay\";i:133;s:16:\"report/affiliate\";i:134;s:25:\"report/affiliate_activity\";i:135;s:22:\"report/affiliate_login\";i:136;s:24:\"report/customer_activity\";i:137;s:22:\"report/customer_credit\";i:138;s:21:\"report/customer_login\";i:139;s:22:\"report/customer_online\";i:140;s:21:\"report/customer_order\";i:141;s:22:\"report/customer_reward\";i:142;s:16:\"report/marketing\";i:143;s:24:\"report/product_purchased\";i:144;s:21:\"report/product_viewed\";i:145;s:18:\"report/sale_coupon\";i:146;s:17:\"report/sale_order\";i:147;s:18:\"report/sale_return\";i:148;s:20:\"report/sale_shipping\";i:149;s:15:\"report/sale_tax\";i:150;s:17:\"sale/custom_field\";i:151;s:13:\"sale/customer\";i:152;s:20:\"sale/customer_ban_ip\";i:153;s:19:\"sale/customer_group\";i:154;s:10:\"sale/order\";i:155;s:14:\"sale/recurring\";i:156;s:11:\"sale/return\";i:157;s:12:\"sale/voucher\";i:158;s:18:\"sale/voucher_theme\";i:159;s:15:\"setting/setting\";i:160;s:13:\"setting/store\";i:161;s:16:\"shipping/auspost\";i:162;s:17:\"shipping/citylink\";i:163;s:14:\"shipping/fedex\";i:164;s:13:\"shipping/flat\";i:165;s:13:\"shipping/free\";i:166;s:13:\"shipping/item\";i:167;s:23:\"shipping/parcelforce_48\";i:168;s:15:\"shipping/pickup\";i:169;s:19:\"shipping/royal_mail\";i:170;s:12:\"shipping/ups\";i:171;s:13:\"shipping/usps\";i:172;s:15:\"shipping/weight\";i:173;s:11:\"tool/backup\";i:174;s:14:\"tool/error_log\";i:175;s:11:\"tool/upload\";i:176;s:12:\"total/coupon\";i:177;s:12:\"total/credit\";i:178;s:14:\"total/handling\";i:179;s:16:\"total/klarna_fee\";i:180;s:19:\"total/low_order_fee\";i:181;s:12:\"total/reward\";i:182;s:14:\"total/shipping\";i:183;s:15:\"total/sub_total\";i:184;s:9:\"total/tax\";i:185;s:11:\"total/total\";i:186;s:13:\"total/voucher\";i:187;s:8:\"user/api\";i:188;s:9:\"user/user\";i:189;s:20:\"user/user_permission\";i:190;s:18:\"payment/pp_express\";}s:6:\"modify\";a:191:{i:0;s:16:\"catalog/add_type\";i:1;s:17:\"catalog/attribute\";i:2;s:23:\"catalog/attribute_group\";i:3;s:16:\"catalog/category\";i:4;s:16:\"catalog/download\";i:5;s:14:\"catalog/filter\";i:6;s:19:\"catalog/information\";i:7;s:20:\"catalog/manufacturer\";i:8;s:14:\"catalog/option\";i:9;s:15:\"catalog/product\";i:10;s:19:\"catalog/product_tag\";i:11;s:17:\"catalog/recurring\";i:12;s:14:\"catalog/review\";i:13;s:11:\"catalog/tag\";i:14;s:18:\"common/column_left\";i:15;s:18:\"common/filemanager\";i:16;s:11:\"common/menu\";i:17;s:14:\"common/profile\";i:18;s:12:\"common/stats\";i:19;s:13:\"design/banner\";i:20;s:13:\"design/layout\";i:21;s:14:\"extension/feed\";i:22;s:15:\"extension/fraud\";i:23;s:19:\"extension/installer\";i:24;s:22:\"extension/modification\";i:25;s:16:\"extension/module\";i:26;s:17:\"extension/openbay\";i:27;s:17:\"extension/payment\";i:28;s:18:\"extension/shipping\";i:29;s:15:\"extension/total\";i:30;s:16:\"feed/google_base\";i:31;s:19:\"feed/google_sitemap\";i:32;s:15:\"feed/openbaypro\";i:33;s:18:\"fraud/fraudlabspro\";i:34;s:13:\"fraud/maxmind\";i:35;s:20:\"localisation/country\";i:36;s:19:\"localisation/coupon\";i:37;s:21:\"localisation/currency\";i:38;s:21:\"localisation/geo_zone\";i:39;s:21:\"localisation/language\";i:40;s:25:\"localisation/length_class\";i:41;s:21:\"localisation/location\";i:42;s:25:\"localisation/order_status\";i:43;s:20:\"localisation/product\";i:44;s:26:\"localisation/return_action\";i:45;s:26:\"localisation/return_reason\";i:46;s:26:\"localisation/return_status\";i:47;s:19:\"localisation/review\";i:48;s:18:\"localisation/state\";i:49;s:25:\"localisation/stock_status\";i:50;s:19:\"localisation/suburb\";i:51;s:22:\"localisation/tax_class\";i:52;s:21:\"localisation/tax_rate\";i:53;s:25:\"localisation/weight_class\";i:54;s:17:\"localisation/zone\";i:55;s:19:\"marketing/affiliate\";i:56;s:17:\"marketing/contact\";i:57;s:16:\"marketing/coupon\";i:58;s:19:\"marketing/marketing\";i:59;s:14:\"module/account\";i:60;s:16:\"module/affiliate\";i:61;s:20:\"module/amazon_button\";i:62;s:19:\"module/amazon_login\";i:63;s:17:\"module/amazon_pay\";i:64;s:13:\"module/banner\";i:65;s:17:\"module/bestseller\";i:66;s:15:\"module/carousel\";i:67;s:15:\"module/category\";i:68;s:19:\"module/ebay_listing\";i:69;s:15:\"module/featured\";i:70;s:13:\"module/filter\";i:71;s:22:\"module/google_hangouts\";i:72;s:11:\"module/html\";i:73;s:18:\"module/information\";i:74;s:13:\"module/latest\";i:75;s:16:\"module/pp_button\";i:76;s:15:\"module/pp_login\";i:77;s:16:\"module/slideshow\";i:78;s:14:\"module/special\";i:79;s:12:\"module/store\";i:80;s:14:\"openbay/amazon\";i:81;s:22:\"openbay/amazon_listing\";i:82;s:22:\"openbay/amazon_product\";i:83;s:16:\"openbay/amazonus\";i:84;s:24:\"openbay/amazonus_listing\";i:85;s:24:\"openbay/amazonus_product\";i:86;s:12:\"openbay/ebay\";i:87;s:20:\"openbay/ebay_profile\";i:88;s:21:\"openbay/ebay_template\";i:89;s:12:\"openbay/etsy\";i:90;s:20:\"openbay/etsy_product\";i:91;s:21:\"openbay/etsy_shipping\";i:92;s:17:\"openbay/etsy_shop\";i:93;s:23:\"payment/amazon_checkout\";i:94;s:24:\"payment/amazon_login_pay\";i:95;s:24:\"payment/authorizenet_aim\";i:96;s:24:\"payment/authorizenet_sim\";i:97;s:21:\"payment/bank_transfer\";i:98;s:22:\"payment/bluepay_hosted\";i:99;s:24:\"payment/bluepay_redirect\";i:100;s:14:\"payment/cheque\";i:101;s:11:\"payment/cod\";i:102;s:17:\"payment/firstdata\";i:103;s:24:\"payment/firstdata_remote\";i:104;s:21:\"payment/free_checkout\";i:105;s:14:\"payment/g2apay\";i:106;s:17:\"payment/globalpay\";i:107;s:24:\"payment/globalpay_remote\";i:108;s:22:\"payment/klarna_account\";i:109;s:22:\"payment/klarna_invoice\";i:110;s:14:\"payment/liqpay\";i:111;s:14:\"payment/nochex\";i:112;s:15:\"payment/paymate\";i:113;s:16:\"payment/paypoint\";i:114;s:13:\"payment/payza\";i:115;s:26:\"payment/perpetual_payments\";i:116;s:18:\"payment/pp_express\";i:117;s:18:\"payment/pp_payflow\";i:118;s:25:\"payment/pp_payflow_iframe\";i:119;s:14:\"payment/pp_pro\";i:120;s:21:\"payment/pp_pro_iframe\";i:121;s:19:\"payment/pp_standard\";i:122;s:14:\"payment/realex\";i:123;s:21:\"payment/realex_remote\";i:124;s:22:\"payment/sagepay_direct\";i:125;s:22:\"payment/sagepay_server\";i:126;s:18:\"payment/sagepay_us\";i:127;s:24:\"payment/securetrading_pp\";i:128;s:24:\"payment/securetrading_ws\";i:129;s:14:\"payment/skrill\";i:130;s:19:\"payment/twocheckout\";i:131;s:28:\"payment/web_payment_software\";i:132;s:16:\"payment/worldpay\";i:133;s:16:\"report/affiliate\";i:134;s:25:\"report/affiliate_activity\";i:135;s:22:\"report/affiliate_login\";i:136;s:24:\"report/customer_activity\";i:137;s:22:\"report/customer_credit\";i:138;s:21:\"report/customer_login\";i:139;s:22:\"report/customer_online\";i:140;s:21:\"report/customer_order\";i:141;s:22:\"report/customer_reward\";i:142;s:16:\"report/marketing\";i:143;s:24:\"report/product_purchased\";i:144;s:21:\"report/product_viewed\";i:145;s:18:\"report/sale_coupon\";i:146;s:17:\"report/sale_order\";i:147;s:18:\"report/sale_return\";i:148;s:20:\"report/sale_shipping\";i:149;s:15:\"report/sale_tax\";i:150;s:17:\"sale/custom_field\";i:151;s:13:\"sale/customer\";i:152;s:20:\"sale/customer_ban_ip\";i:153;s:19:\"sale/customer_group\";i:154;s:10:\"sale/order\";i:155;s:14:\"sale/recurring\";i:156;s:11:\"sale/return\";i:157;s:12:\"sale/voucher\";i:158;s:18:\"sale/voucher_theme\";i:159;s:15:\"setting/setting\";i:160;s:13:\"setting/store\";i:161;s:16:\"shipping/auspost\";i:162;s:17:\"shipping/citylink\";i:163;s:14:\"shipping/fedex\";i:164;s:13:\"shipping/flat\";i:165;s:13:\"shipping/free\";i:166;s:13:\"shipping/item\";i:167;s:23:\"shipping/parcelforce_48\";i:168;s:15:\"shipping/pickup\";i:169;s:19:\"shipping/royal_mail\";i:170;s:12:\"shipping/ups\";i:171;s:13:\"shipping/usps\";i:172;s:15:\"shipping/weight\";i:173;s:11:\"tool/backup\";i:174;s:14:\"tool/error_log\";i:175;s:11:\"tool/upload\";i:176;s:12:\"total/coupon\";i:177;s:12:\"total/credit\";i:178;s:14:\"total/handling\";i:179;s:16:\"total/klarna_fee\";i:180;s:19:\"total/low_order_fee\";i:181;s:12:\"total/reward\";i:182;s:14:\"total/shipping\";i:183;s:15:\"total/sub_total\";i:184;s:9:\"total/tax\";i:185;s:11:\"total/total\";i:186;s:13:\"total/voucher\";i:187;s:8:\"user/api\";i:188;s:9:\"user/user\";i:189;s:20:\"user/user_permission\";i:190;s:18:\"payment/pp_express\";}}'),
(10, 'Demonstration', '');

-- --------------------------------------------------------

--
-- 表的结构 `oc_voucher`
--

CREATE TABLE `oc_voucher` (
  `voucher_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `code` varchar(10) NOT NULL,
  `from_name` varchar(64) NOT NULL,
  `from_email` varchar(96) NOT NULL,
  `to_name` varchar(64) NOT NULL,
  `to_email` varchar(96) NOT NULL,
  `voucher_theme_id` int(11) NOT NULL,
  `message` text NOT NULL,
  `amount` decimal(15,4) NOT NULL,
  `status` tinyint(1) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_voucher_history`
--

CREATE TABLE `oc_voucher_history` (
  `voucher_history_id` int(11) NOT NULL,
  `voucher_id` int(11) NOT NULL,
  `order_id` int(11) NOT NULL,
  `amount` decimal(15,4) NOT NULL,
  `date_added` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_voucher_theme`
--

CREATE TABLE `oc_voucher_theme` (
  `voucher_theme_id` int(11) NOT NULL,
  `image` varchar(255) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_voucher_theme`
--

INSERT INTO `oc_voucher_theme` (`voucher_theme_id`, `image`) VALUES
(8, 'catalog/demo/canon_eos_5d_2.jpg'),
(7, 'catalog/demo/gift-voucher-birthday.jpg'),
(6, 'catalog/demo/apple_logo.jpg');

-- --------------------------------------------------------

--
-- 表的结构 `oc_voucher_theme_description`
--

CREATE TABLE `oc_voucher_theme_description` (
  `voucher_theme_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `name` varchar(32) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_voucher_theme_description`
--

INSERT INTO `oc_voucher_theme_description` (`voucher_theme_id`, `language_id`, `name`) VALUES
(6, 1, 'Christmas'),
(7, 1, 'Birthday'),
(8, 1, 'General');

-- --------------------------------------------------------

--
-- 表的结构 `oc_weight_class`
--

CREATE TABLE `oc_weight_class` (
  `weight_class_id` int(11) NOT NULL,
  `value` decimal(15,8) NOT NULL DEFAULT '0.00000000'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_weight_class`
--

INSERT INTO `oc_weight_class` (`weight_class_id`, `value`) VALUES
(1, '1.00000000'),
(2, '1000.00000000'),
(5, '2.20460000'),
(6, '35.27400000');

-- --------------------------------------------------------

--
-- 表的结构 `oc_weight_class_description`
--

CREATE TABLE `oc_weight_class_description` (
  `weight_class_id` int(11) NOT NULL,
  `language_id` int(11) NOT NULL,
  `title` varchar(32) NOT NULL,
  `unit` varchar(4) NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_weight_class_description`
--

INSERT INTO `oc_weight_class_description` (`weight_class_id`, `language_id`, `title`, `unit`) VALUES
(1, 1, 'Kilogram', 'kg'),
(2, 1, 'Gram', 'g'),
(5, 1, 'Pound ', 'lb'),
(6, 1, 'Ounce', 'oz');

-- --------------------------------------------------------

--
-- 表的结构 `oc_zone`
--

CREATE TABLE `oc_zone` (
  `zone_id` int(11) NOT NULL,
  `country_id` int(11) NOT NULL,
  `name` varchar(128) NOT NULL,
  `code` varchar(32) NOT NULL,
  `fee` decimal(10,2) NOT NULL,
  `status` tinyint(1) NOT NULL DEFAULT '1'
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- 表的结构 `oc_zone_to_geo_zone`
--

CREATE TABLE `oc_zone_to_geo_zone` (
  `zone_to_geo_zone_id` int(11) NOT NULL,
  `country_id` int(11) NOT NULL,
  `state_id` int(11) NOT NULL DEFAULT '0',
  `suburb_id` int(11) NOT NULL DEFAULT '0',
  `geo_zone_id` int(11) NOT NULL,
  `fee` decimal(10,2) NOT NULL DEFAULT '0.00',
  `sort_order` int(3) NOT NULL DEFAULT '0',
  `date_added` datetime NOT NULL,
  `date_modified` datetime NOT NULL
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- 转存表中的数据 `oc_zone_to_geo_zone`
--

INSERT INTO `oc_zone_to_geo_zone` (`zone_to_geo_zone_id`, `country_id`, `state_id`, `suburb_id`, `geo_zone_id`, `fee`, `sort_order`, `date_added`, `date_modified`) VALUES
(129, 1, 2, 4, 1, '5.00', 1, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(128, 1, 2, 2, 1, '6.00', 2, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(127, 1, 2, 8, 1, '5.00', 3, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(126, 1, 2, 6, 1, '5.00', 4, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(125, 1, 2, 9, 1, '5.00', 5, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(124, 1, 2, 3, 1, '3.00', 6, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(123, 1, 2, 7, 1, '0.00', 7, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(122, 1, 2, 12, 1, '5.00', 8, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(121, 1, 2, 5, 1, '3.00', 9, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(120, 1, 2, 10, 1, '6.00', 10, '2017-07-03 12:14:10', '0000-00-00 00:00:00'),
(119, 1, 2, 11, 1, '8.00', 11, '2017-07-03 12:14:10', '0000-00-00 00:00:00');

-- --------------------------------------------------------

--
-- 表的结构 `users`
--

CREATE TABLE `users` (
  `id` int(10) UNSIGNED NOT NULL,
  `name` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `email_verified_at` timestamp NULL DEFAULT NULL,
  `password` varchar(255) COLLATE utf8mb4_unicode_ci NOT NULL,
  `remember_token` varchar(100) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `created_at` timestamp NULL DEFAULT NULL,
  `updated_at` timestamp NULL DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

--
-- 转储表的索引
--

--
-- 表的索引 `migrations`
--
ALTER TABLE `migrations`
  ADD PRIMARY KEY (`id`);

--
-- 表的索引 `oc_address`
--
ALTER TABLE `oc_address`
  ADD PRIMARY KEY (`address_id`),
  ADD KEY `customer_id` (`customer_id`);

--
-- 表的索引 `oc_affiliate`
--
ALTER TABLE `oc_affiliate`
  ADD PRIMARY KEY (`affiliate_id`);

--
-- 表的索引 `oc_affiliate_activity`
--
ALTER TABLE `oc_affiliate_activity`
  ADD PRIMARY KEY (`activity_id`);

--
-- 表的索引 `oc_affiliate_login`
--
ALTER TABLE `oc_affiliate_login`
  ADD PRIMARY KEY (`affiliate_login_id`),
  ADD KEY `email` (`email`),
  ADD KEY `ip` (`ip`);

--
-- 表的索引 `oc_affiliate_transaction`
--
ALTER TABLE `oc_affiliate_transaction`
  ADD PRIMARY KEY (`affiliate_transaction_id`);

--
-- 表的索引 `oc_api`
--
ALTER TABLE `oc_api`
  ADD PRIMARY KEY (`api_id`);

--
-- 表的索引 `oc_attribute`
--
ALTER TABLE `oc_attribute`
  ADD PRIMARY KEY (`attribute_id`);

--
-- 表的索引 `oc_attribute_description`
--
ALTER TABLE `oc_attribute_description`
  ADD PRIMARY KEY (`attribute_id`,`language_id`);

--
-- 表的索引 `oc_attribute_group`
--
ALTER TABLE `oc_attribute_group`
  ADD PRIMARY KEY (`attribute_group_id`);

--
-- 表的索引 `oc_attribute_group_description`
--
ALTER TABLE `oc_attribute_group_description`
  ADD PRIMARY KEY (`attribute_group_id`,`language_id`);

--
-- 表的索引 `oc_banner`
--
ALTER TABLE `oc_banner`
  ADD PRIMARY KEY (`banner_id`);

--
-- 表的索引 `oc_banner_image`
--
ALTER TABLE `oc_banner_image`
  ADD PRIMARY KEY (`banner_image_id`);

--
-- 表的索引 `oc_banner_image_description`
--
ALTER TABLE `oc_banner_image_description`
  ADD PRIMARY KEY (`banner_image_id`,`language_id`);

--
-- 表的索引 `oc_category`
--
ALTER TABLE `oc_category`
  ADD PRIMARY KEY (`category_id`),
  ADD KEY `parent_id` (`parent_id`);

--
-- 表的索引 `oc_category_description`
--
ALTER TABLE `oc_category_description`
  ADD PRIMARY KEY (`category_id`,`language_id`),
  ADD KEY `name` (`name`);

--
-- 表的索引 `oc_category_filter`
--
ALTER TABLE `oc_category_filter`
  ADD PRIMARY KEY (`category_id`,`filter_id`);

--
-- 表的索引 `oc_category_path`
--
ALTER TABLE `oc_category_path`
  ADD PRIMARY KEY (`category_id`,`path_id`);

--
-- 表的索引 `oc_category_to_layout`
--
ALTER TABLE `oc_category_to_layout`
  ADD PRIMARY KEY (`category_id`,`store_id`);

--
-- 表的索引 `oc_category_to_store`
--
ALTER TABLE `oc_category_to_store`
  ADD PRIMARY KEY (`category_id`,`store_id`);

--
-- 表的索引 `oc_country`
--
ALTER TABLE `oc_country`
  ADD PRIMARY KEY (`country_id`);

--
-- 表的索引 `oc_coupon`
--
ALTER TABLE `oc_coupon`
  ADD PRIMARY KEY (`coupon_id`);

--
-- 表的索引 `oc_coupon_category`
--
ALTER TABLE `oc_coupon_category`
  ADD PRIMARY KEY (`coupon_id`,`category_id`);

--
-- 表的索引 `oc_coupon_history`
--
ALTER TABLE `oc_coupon_history`
  ADD PRIMARY KEY (`coupon_history_id`);

--
-- 表的索引 `oc_coupon_product`
--
ALTER TABLE `oc_coupon_product`
  ADD PRIMARY KEY (`coupon_product_id`);

--
-- 表的索引 `oc_currency`
--
ALTER TABLE `oc_currency`
  ADD PRIMARY KEY (`currency_id`);

--
-- 表的索引 `oc_customer`
--
ALTER TABLE `oc_customer`
  ADD PRIMARY KEY (`customer_id`);

--
-- 表的索引 `oc_customer_activity`
--
ALTER TABLE `oc_customer_activity`
  ADD PRIMARY KEY (`activity_id`);

--
-- 表的索引 `oc_customer_ban_ip`
--
ALTER TABLE `oc_customer_ban_ip`
  ADD PRIMARY KEY (`customer_ban_ip_id`),
  ADD KEY `ip` (`ip`);

--
-- 表的索引 `oc_customer_group`
--
ALTER TABLE `oc_customer_group`
  ADD PRIMARY KEY (`customer_group_id`);

--
-- 表的索引 `oc_customer_group_description`
--
ALTER TABLE `oc_customer_group_description`
  ADD PRIMARY KEY (`customer_group_id`,`language_id`);

--
-- 表的索引 `oc_customer_history`
--
ALTER TABLE `oc_customer_history`
  ADD PRIMARY KEY (`customer_history_id`);

--
-- 表的索引 `oc_customer_ip`
--
ALTER TABLE `oc_customer_ip`
  ADD PRIMARY KEY (`customer_ip_id`),
  ADD KEY `ip` (`ip`);

--
-- 表的索引 `oc_customer_login`
--
ALTER TABLE `oc_customer_login`
  ADD PRIMARY KEY (`customer_login_id`),
  ADD KEY `email` (`email`),
  ADD KEY `ip` (`ip`);

--
-- 表的索引 `oc_customer_online`
--
ALTER TABLE `oc_customer_online`
  ADD PRIMARY KEY (`ip`);

--
-- 表的索引 `oc_customer_reward`
--
ALTER TABLE `oc_customer_reward`
  ADD PRIMARY KEY (`customer_reward_id`);

--
-- 表的索引 `oc_customer_transaction`
--
ALTER TABLE `oc_customer_transaction`
  ADD PRIMARY KEY (`customer_transaction_id`);

--
-- 表的索引 `oc_custom_field`
--
ALTER TABLE `oc_custom_field`
  ADD PRIMARY KEY (`custom_field_id`);

--
-- 表的索引 `oc_custom_field_customer_group`
--
ALTER TABLE `oc_custom_field_customer_group`
  ADD PRIMARY KEY (`custom_field_id`,`customer_group_id`);

--
-- 表的索引 `oc_custom_field_description`
--
ALTER TABLE `oc_custom_field_description`
  ADD PRIMARY KEY (`custom_field_id`,`language_id`);

--
-- 表的索引 `oc_custom_field_value`
--
ALTER TABLE `oc_custom_field_value`
  ADD PRIMARY KEY (`custom_field_value_id`);

--
-- 表的索引 `oc_custom_field_value_description`
--
ALTER TABLE `oc_custom_field_value_description`
  ADD PRIMARY KEY (`custom_field_value_id`,`language_id`);

--
-- 表的索引 `oc_download`
--
ALTER TABLE `oc_download`
  ADD PRIMARY KEY (`download_id`);

--
-- 表的索引 `oc_download_description`
--
ALTER TABLE `oc_download_description`
  ADD PRIMARY KEY (`download_id`,`language_id`);

--
-- 表的索引 `oc_event`
--
ALTER TABLE `oc_event`
  ADD PRIMARY KEY (`event_id`);

--
-- 表的索引 `oc_extension`
--
ALTER TABLE `oc_extension`
  ADD PRIMARY KEY (`extension_id`);

--
-- 表的索引 `oc_filter`
--
ALTER TABLE `oc_filter`
  ADD PRIMARY KEY (`filter_id`);

--
-- 表的索引 `oc_filter_description`
--
ALTER TABLE `oc_filter_description`
  ADD PRIMARY KEY (`filter_id`,`language_id`);

--
-- 表的索引 `oc_filter_group`
--
ALTER TABLE `oc_filter_group`
  ADD PRIMARY KEY (`filter_group_id`);

--
-- 表的索引 `oc_filter_group_description`
--
ALTER TABLE `oc_filter_group_description`
  ADD PRIMARY KEY (`filter_group_id`,`language_id`);

--
-- 表的索引 `oc_geo_zone`
--
ALTER TABLE `oc_geo_zone`
  ADD PRIMARY KEY (`geo_zone_id`);

--
-- 表的索引 `oc_information`
--
ALTER TABLE `oc_information`
  ADD PRIMARY KEY (`information_id`);

--
-- 表的索引 `oc_information_description`
--
ALTER TABLE `oc_information_description`
  ADD PRIMARY KEY (`information_id`,`language_id`);

--
-- 表的索引 `oc_information_to_layout`
--
ALTER TABLE `oc_information_to_layout`
  ADD PRIMARY KEY (`information_id`,`store_id`);

--
-- 表的索引 `oc_information_to_store`
--
ALTER TABLE `oc_information_to_store`
  ADD PRIMARY KEY (`information_id`,`store_id`);

--
-- 表的索引 `oc_language`
--
ALTER TABLE `oc_language`
  ADD PRIMARY KEY (`language_id`),
  ADD KEY `name` (`name`);

--
-- 表的索引 `oc_layout`
--
ALTER TABLE `oc_layout`
  ADD PRIMARY KEY (`layout_id`);

--
-- 表的索引 `oc_layout_module`
--
ALTER TABLE `oc_layout_module`
  ADD PRIMARY KEY (`layout_module_id`);

--
-- 表的索引 `oc_layout_route`
--
ALTER TABLE `oc_layout_route`
  ADD PRIMARY KEY (`layout_route_id`);

--
-- 表的索引 `oc_length_class`
--
ALTER TABLE `oc_length_class`
  ADD PRIMARY KEY (`length_class_id`);

--
-- 表的索引 `oc_length_class_description`
--
ALTER TABLE `oc_length_class_description`
  ADD PRIMARY KEY (`length_class_id`,`language_id`);

--
-- 表的索引 `oc_location`
--
ALTER TABLE `oc_location`
  ADD PRIMARY KEY (`location_id`),
  ADD KEY `name` (`name`);

--
-- 表的索引 `oc_manufacturer`
--
ALTER TABLE `oc_manufacturer`
  ADD PRIMARY KEY (`manufacturer_id`);

--
-- 表的索引 `oc_manufacturer_to_store`
--
ALTER TABLE `oc_manufacturer_to_store`
  ADD PRIMARY KEY (`manufacturer_id`,`store_id`);

--
-- 表的索引 `oc_marketing`
--
ALTER TABLE `oc_marketing`
  ADD PRIMARY KEY (`marketing_id`);

--
-- 表的索引 `oc_modification`
--
ALTER TABLE `oc_modification`
  ADD PRIMARY KEY (`modification_id`);

--
-- 表的索引 `oc_module`
--
ALTER TABLE `oc_module`
  ADD PRIMARY KEY (`module_id`);

--
-- 表的索引 `oc_option`
--
ALTER TABLE `oc_option`
  ADD PRIMARY KEY (`option_id`);

--
-- 表的索引 `oc_option_description`
--
ALTER TABLE `oc_option_description`
  ADD PRIMARY KEY (`option_id`,`language_id`);

--
-- 表的索引 `oc_option_value`
--
ALTER TABLE `oc_option_value`
  ADD PRIMARY KEY (`option_value_id`);

--
-- 表的索引 `oc_option_value_description`
--
ALTER TABLE `oc_option_value_description`
  ADD PRIMARY KEY (`option_value_id`,`language_id`);

--
-- 表的索引 `oc_order`
--
ALTER TABLE `oc_order`
  ADD PRIMARY KEY (`order_id`);

--
-- 表的索引 `oc_order_coupon`
--
ALTER TABLE `oc_order_coupon`
  ADD PRIMARY KEY (`order_coupon_id`);

--
-- 表的索引 `oc_order_custom_field`
--
ALTER TABLE `oc_order_custom_field`
  ADD PRIMARY KEY (`order_custom_field_id`);

--
-- 表的索引 `oc_order_ext`
--
ALTER TABLE `oc_order_ext`
  ADD PRIMARY KEY (`order_ext_id`);

--
-- 表的索引 `oc_order_history`
--
ALTER TABLE `oc_order_history`
  ADD PRIMARY KEY (`order_history_id`);

--
-- 表的索引 `oc_order_option`
--
ALTER TABLE `oc_order_option`
  ADD PRIMARY KEY (`order_option_id`);

--
-- 表的索引 `oc_order_product`
--
ALTER TABLE `oc_order_product`
  ADD PRIMARY KEY (`order_product_id`);

--
-- 表的索引 `oc_order_recurring`
--
ALTER TABLE `oc_order_recurring`
  ADD PRIMARY KEY (`order_recurring_id`);

--
-- 表的索引 `oc_order_recurring_transaction`
--
ALTER TABLE `oc_order_recurring_transaction`
  ADD PRIMARY KEY (`order_recurring_transaction_id`);

--
-- 表的索引 `oc_order_status`
--
ALTER TABLE `oc_order_status`
  ADD PRIMARY KEY (`order_status_id`,`language_id`);

--
-- 表的索引 `oc_order_total`
--
ALTER TABLE `oc_order_total`
  ADD PRIMARY KEY (`order_total_id`),
  ADD KEY `order_id` (`order_id`);

--
-- 表的索引 `oc_order_voucher`
--
ALTER TABLE `oc_order_voucher`
  ADD PRIMARY KEY (`order_voucher_id`);

--
-- 表的索引 `oc_paypal_order`
--
ALTER TABLE `oc_paypal_order`
  ADD PRIMARY KEY (`paypal_order_id`);

--
-- 表的索引 `oc_paypal_order_transaction`
--
ALTER TABLE `oc_paypal_order_transaction`
  ADD PRIMARY KEY (`paypal_order_transaction_id`);

--
-- 表的索引 `oc_product`
--
ALTER TABLE `oc_product`
  ADD PRIMARY KEY (`product_id`);

--
-- 表的索引 `oc_product_add_type`
--
ALTER TABLE `oc_product_add_type`
  ADD PRIMARY KEY (`add_type_id`,`language_id`);

--
-- 表的索引 `oc_product_attribute`
--
ALTER TABLE `oc_product_attribute`
  ADD PRIMARY KEY (`product_id`,`attribute_id`,`language_id`);

--
-- 表的索引 `oc_product_description`
--
ALTER TABLE `oc_product_description`
  ADD PRIMARY KEY (`product_id`,`language_id`),
  ADD KEY `name` (`name`);

--
-- 表的索引 `oc_product_discount`
--
ALTER TABLE `oc_product_discount`
  ADD PRIMARY KEY (`product_discount_id`),
  ADD KEY `product_id` (`product_id`);

--
-- 表的索引 `oc_product_ext`
--
ALTER TABLE `oc_product_ext`
  ADD PRIMARY KEY (`product_ext_id`,`language_id`);

--
-- 表的索引 `oc_product_filter`
--
ALTER TABLE `oc_product_filter`
  ADD PRIMARY KEY (`product_id`,`filter_id`);

--
-- 表的索引 `oc_product_image`
--
ALTER TABLE `oc_product_image`
  ADD PRIMARY KEY (`product_image_id`),
  ADD KEY `product_id` (`product_id`);

--
-- 表的索引 `oc_product_option`
--
ALTER TABLE `oc_product_option`
  ADD PRIMARY KEY (`product_option_id`);

--
-- 表的索引 `oc_product_option_value`
--
ALTER TABLE `oc_product_option_value`
  ADD PRIMARY KEY (`product_option_value_id`);

--
-- 表的索引 `oc_product_recurring`
--
ALTER TABLE `oc_product_recurring`
  ADD PRIMARY KEY (`product_id`,`recurring_id`,`customer_group_id`);

--
-- 表的索引 `oc_product_related`
--
ALTER TABLE `oc_product_related`
  ADD PRIMARY KEY (`product_id`,`related_id`);

--
-- 表的索引 `oc_product_reward`
--
ALTER TABLE `oc_product_reward`
  ADD PRIMARY KEY (`product_reward_id`);

--
-- 表的索引 `oc_product_special`
--
ALTER TABLE `oc_product_special`
  ADD PRIMARY KEY (`product_special_id`),
  ADD KEY `product_id` (`product_id`);

--
-- 表的索引 `oc_product_tag`
--
ALTER TABLE `oc_product_tag`
  ADD PRIMARY KEY (`product_tag_id`);

--
-- 表的索引 `oc_product_to_category`
--
ALTER TABLE `oc_product_to_category`
  ADD PRIMARY KEY (`product_id`,`category_id`),
  ADD KEY `category_id` (`category_id`);

--
-- 表的索引 `oc_product_to_download`
--
ALTER TABLE `oc_product_to_download`
  ADD PRIMARY KEY (`product_id`,`download_id`);

--
-- 表的索引 `oc_product_to_layout`
--
ALTER TABLE `oc_product_to_layout`
  ADD PRIMARY KEY (`product_id`,`store_id`);

--
-- 表的索引 `oc_product_to_store`
--
ALTER TABLE `oc_product_to_store`
  ADD PRIMARY KEY (`product_id`,`store_id`);

--
-- 表的索引 `oc_recurring`
--
ALTER TABLE `oc_recurring`
  ADD PRIMARY KEY (`recurring_id`);

--
-- 表的索引 `oc_recurring_description`
--
ALTER TABLE `oc_recurring_description`
  ADD PRIMARY KEY (`recurring_id`,`language_id`);

--
-- 表的索引 `oc_return`
--
ALTER TABLE `oc_return`
  ADD PRIMARY KEY (`return_id`);

--
-- 表的索引 `oc_return_action`
--
ALTER TABLE `oc_return_action`
  ADD PRIMARY KEY (`return_action_id`,`language_id`);

--
-- 表的索引 `oc_return_history`
--
ALTER TABLE `oc_return_history`
  ADD PRIMARY KEY (`return_history_id`);

--
-- 表的索引 `oc_return_reason`
--
ALTER TABLE `oc_return_reason`
  ADD PRIMARY KEY (`return_reason_id`,`language_id`);

--
-- 表的索引 `oc_return_status`
--
ALTER TABLE `oc_return_status`
  ADD PRIMARY KEY (`return_status_id`,`language_id`);

--
-- 表的索引 `oc_review`
--
ALTER TABLE `oc_review`
  ADD PRIMARY KEY (`review_id`),
  ADD KEY `product_id` (`product_id`);

--
-- 表的索引 `oc_setting`
--
ALTER TABLE `oc_setting`
  ADD PRIMARY KEY (`setting_id`);

--
-- 表的索引 `oc_shop_coupon`
--
ALTER TABLE `oc_shop_coupon`
  ADD PRIMARY KEY (`shop_coupon_id`);

--
-- 表的索引 `oc_shop_coupon_product`
--
ALTER TABLE `oc_shop_coupon_product`
  ADD PRIMARY KEY (`product_id`);

--
-- 表的索引 `oc_shop_image`
--
ALTER TABLE `oc_shop_image`
  ADD PRIMARY KEY (`shop_image_id`),
  ADD KEY `shop_id` (`location_id`);

--
-- 表的索引 `oc_shop_info`
--
ALTER TABLE `oc_shop_info`
  ADD PRIMARY KEY (`shop_info_id`);

--
-- 表的索引 `oc_shop_tag`
--
ALTER TABLE `oc_shop_tag`
  ADD PRIMARY KEY (`tag_id`);

--
-- 表的索引 `oc_shop_time`
--
ALTER TABLE `oc_shop_time`
  ADD PRIMARY KEY (`shop_time_id`);

--
-- 表的索引 `oc_state`
--
ALTER TABLE `oc_state`
  ADD PRIMARY KEY (`state_id`);

--
-- 表的索引 `oc_stock_status`
--
ALTER TABLE `oc_stock_status`
  ADD PRIMARY KEY (`stock_status_id`,`language_id`);

--
-- 表的索引 `oc_store`
--
ALTER TABLE `oc_store`
  ADD PRIMARY KEY (`store_id`);

--
-- 表的索引 `oc_suburb`
--
ALTER TABLE `oc_suburb`
  ADD PRIMARY KEY (`suburb_id`);

--
-- 表的索引 `oc_table_link`
--
ALTER TABLE `oc_table_link`
  ADD PRIMARY KEY (`link_id`),
  ADD KEY `table_link` (`table_link`,`status`);

--
-- 表的索引 `oc_table_linksub`
--
ALTER TABLE `oc_table_linksub`
  ADD PRIMARY KEY (`link_id`,`linksub_id`),
  ADD KEY `table_linksub` (`downloaded`,`sub_status`,`client_ip`,`order_id`);

--
-- 表的索引 `oc_tax_class`
--
ALTER TABLE `oc_tax_class`
  ADD PRIMARY KEY (`tax_class_id`);

--
-- 表的索引 `oc_tax_rate`
--
ALTER TABLE `oc_tax_rate`
  ADD PRIMARY KEY (`tax_rate_id`);

--
-- 表的索引 `oc_tax_rate_to_customer_group`
--
ALTER TABLE `oc_tax_rate_to_customer_group`
  ADD PRIMARY KEY (`tax_rate_id`,`customer_group_id`);

--
-- 表的索引 `oc_tax_rule`
--
ALTER TABLE `oc_tax_rule`
  ADD PRIMARY KEY (`tax_rule_id`);

--
-- 表的索引 `oc_upload`
--
ALTER TABLE `oc_upload`
  ADD PRIMARY KEY (`upload_id`);

--
-- 表的索引 `oc_url_alias`
--
ALTER TABLE `oc_url_alias`
  ADD PRIMARY KEY (`url_alias_id`),
  ADD KEY `query` (`query`),
  ADD KEY `keyword` (`keyword`);

--
-- 表的索引 `oc_user`
--
ALTER TABLE `oc_user`
  ADD PRIMARY KEY (`id`);

--
-- 表的索引 `oc_user_group`
--
ALTER TABLE `oc_user_group`
  ADD PRIMARY KEY (`user_group_id`);

--
-- 表的索引 `oc_voucher`
--
ALTER TABLE `oc_voucher`
  ADD PRIMARY KEY (`voucher_id`);

--
-- 表的索引 `oc_voucher_history`
--
ALTER TABLE `oc_voucher_history`
  ADD PRIMARY KEY (`voucher_history_id`);

--
-- 表的索引 `oc_voucher_theme`
--
ALTER TABLE `oc_voucher_theme`
  ADD PRIMARY KEY (`voucher_theme_id`);

--
-- 表的索引 `oc_voucher_theme_description`
--
ALTER TABLE `oc_voucher_theme_description`
  ADD PRIMARY KEY (`voucher_theme_id`,`language_id`);

--
-- 表的索引 `oc_weight_class`
--
ALTER TABLE `oc_weight_class`
  ADD PRIMARY KEY (`weight_class_id`);

--
-- 表的索引 `oc_weight_class_description`
--
ALTER TABLE `oc_weight_class_description`
  ADD PRIMARY KEY (`weight_class_id`,`language_id`);

--
-- 表的索引 `oc_zone`
--
ALTER TABLE `oc_zone`
  ADD PRIMARY KEY (`zone_id`);

--
-- 表的索引 `oc_zone_to_geo_zone`
--
ALTER TABLE `oc_zone_to_geo_zone`
  ADD PRIMARY KEY (`zone_to_geo_zone_id`);

--
-- 表的索引 `users`
--
ALTER TABLE `users`
  ADD PRIMARY KEY (`id`);

--
-- 在导出的表使用AUTO_INCREMENT
--

--
-- 使用表AUTO_INCREMENT `migrations`
--
ALTER TABLE `migrations`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_address`
--
ALTER TABLE `oc_address`
  MODIFY `address_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=23;

--
-- 使用表AUTO_INCREMENT `oc_affiliate`
--
ALTER TABLE `oc_affiliate`
  MODIFY `affiliate_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_affiliate_activity`
--
ALTER TABLE `oc_affiliate_activity`
  MODIFY `activity_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_affiliate_login`
--
ALTER TABLE `oc_affiliate_login`
  MODIFY `affiliate_login_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_affiliate_transaction`
--
ALTER TABLE `oc_affiliate_transaction`
  MODIFY `affiliate_transaction_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_api`
--
ALTER TABLE `oc_api`
  MODIFY `api_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- 使用表AUTO_INCREMENT `oc_attribute`
--
ALTER TABLE `oc_attribute`
  MODIFY `attribute_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- 使用表AUTO_INCREMENT `oc_attribute_group`
--
ALTER TABLE `oc_attribute_group`
  MODIFY `attribute_group_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- 使用表AUTO_INCREMENT `oc_banner`
--
ALTER TABLE `oc_banner`
  MODIFY `banner_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- 使用表AUTO_INCREMENT `oc_banner_image`
--
ALTER TABLE `oc_banner_image`
  MODIFY `banner_image_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=99;

--
-- 使用表AUTO_INCREMENT `oc_category`
--
ALTER TABLE `oc_category`
  MODIFY `category_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- 使用表AUTO_INCREMENT `oc_country`
--
ALTER TABLE `oc_country`
  MODIFY `country_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- 使用表AUTO_INCREMENT `oc_coupon`
--
ALTER TABLE `oc_coupon`
  MODIFY `coupon_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- 使用表AUTO_INCREMENT `oc_coupon_history`
--
ALTER TABLE `oc_coupon_history`
  MODIFY `coupon_history_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_coupon_product`
--
ALTER TABLE `oc_coupon_product`
  MODIFY `coupon_product_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_currency`
--
ALTER TABLE `oc_currency`
  MODIFY `currency_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5;

--
-- 使用表AUTO_INCREMENT `oc_customer`
--
ALTER TABLE `oc_customer`
  MODIFY `customer_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- 使用表AUTO_INCREMENT `oc_customer_activity`
--
ALTER TABLE `oc_customer_activity`
  MODIFY `activity_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=382;

--
-- 使用表AUTO_INCREMENT `oc_customer_ban_ip`
--
ALTER TABLE `oc_customer_ban_ip`
  MODIFY `customer_ban_ip_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_customer_group`
--
ALTER TABLE `oc_customer_group`
  MODIFY `customer_group_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- 使用表AUTO_INCREMENT `oc_customer_history`
--
ALTER TABLE `oc_customer_history`
  MODIFY `customer_history_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_customer_ip`
--
ALTER TABLE `oc_customer_ip`
  MODIFY `customer_ip_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=24;

--
-- 使用表AUTO_INCREMENT `oc_customer_login`
--
ALTER TABLE `oc_customer_login`
  MODIFY `customer_login_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- 使用表AUTO_INCREMENT `oc_customer_reward`
--
ALTER TABLE `oc_customer_reward`
  MODIFY `customer_reward_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_customer_transaction`
--
ALTER TABLE `oc_customer_transaction`
  MODIFY `customer_transaction_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_custom_field`
--
ALTER TABLE `oc_custom_field`
  MODIFY `custom_field_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_custom_field_value`
--
ALTER TABLE `oc_custom_field_value`
  MODIFY `custom_field_value_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_download`
--
ALTER TABLE `oc_download`
  MODIFY `download_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_event`
--
ALTER TABLE `oc_event`
  MODIFY `event_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_extension`
--
ALTER TABLE `oc_extension`
  MODIFY `extension_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=435;

--
-- 使用表AUTO_INCREMENT `oc_filter`
--
ALTER TABLE `oc_filter`
  MODIFY `filter_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_filter_group`
--
ALTER TABLE `oc_filter_group`
  MODIFY `filter_group_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_geo_zone`
--
ALTER TABLE `oc_geo_zone`
  MODIFY `geo_zone_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- 使用表AUTO_INCREMENT `oc_information`
--
ALTER TABLE `oc_information`
  MODIFY `information_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- 使用表AUTO_INCREMENT `oc_language`
--
ALTER TABLE `oc_language`
  MODIFY `language_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=2;

--
-- 使用表AUTO_INCREMENT `oc_layout`
--
ALTER TABLE `oc_layout`
  MODIFY `layout_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=14;

--
-- 使用表AUTO_INCREMENT `oc_layout_module`
--
ALTER TABLE `oc_layout_module`
  MODIFY `layout_module_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=74;

--
-- 使用表AUTO_INCREMENT `oc_layout_route`
--
ALTER TABLE `oc_layout_route`
  MODIFY `layout_route_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=54;

--
-- 使用表AUTO_INCREMENT `oc_length_class`
--
ALTER TABLE `oc_length_class`
  MODIFY `length_class_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- 使用表AUTO_INCREMENT `oc_length_class_description`
--
ALTER TABLE `oc_length_class_description`
  MODIFY `length_class_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- 使用表AUTO_INCREMENT `oc_location`
--
ALTER TABLE `oc_location`
  MODIFY `location_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- 使用表AUTO_INCREMENT `oc_manufacturer`
--
ALTER TABLE `oc_manufacturer`
  MODIFY `manufacturer_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- 使用表AUTO_INCREMENT `oc_marketing`
--
ALTER TABLE `oc_marketing`
  MODIFY `marketing_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_modification`
--
ALTER TABLE `oc_modification`
  MODIFY `modification_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_module`
--
ALTER TABLE `oc_module`
  MODIFY `module_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=31;

--
-- 使用表AUTO_INCREMENT `oc_option`
--
ALTER TABLE `oc_option`
  MODIFY `option_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- 使用表AUTO_INCREMENT `oc_option_value`
--
ALTER TABLE `oc_option_value`
  MODIFY `option_value_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=31;

--
-- 使用表AUTO_INCREMENT `oc_order`
--
ALTER TABLE `oc_order`
  MODIFY `order_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=147;

--
-- 使用表AUTO_INCREMENT `oc_order_coupon`
--
ALTER TABLE `oc_order_coupon`
  MODIFY `order_coupon_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=147;

--
-- 使用表AUTO_INCREMENT `oc_order_custom_field`
--
ALTER TABLE `oc_order_custom_field`
  MODIFY `order_custom_field_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_order_ext`
--
ALTER TABLE `oc_order_ext`
  MODIFY `order_ext_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=57;

--
-- 使用表AUTO_INCREMENT `oc_order_history`
--
ALTER TABLE `oc_order_history`
  MODIFY `order_history_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=141;

--
-- 使用表AUTO_INCREMENT `oc_order_option`
--
ALTER TABLE `oc_order_option`
  MODIFY `order_option_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=28;

--
-- 使用表AUTO_INCREMENT `oc_order_product`
--
ALTER TABLE `oc_order_product`
  MODIFY `order_product_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=175;

--
-- 使用表AUTO_INCREMENT `oc_order_recurring`
--
ALTER TABLE `oc_order_recurring`
  MODIFY `order_recurring_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_order_recurring_transaction`
--
ALTER TABLE `oc_order_recurring_transaction`
  MODIFY `order_recurring_transaction_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_order_status`
--
ALTER TABLE `oc_order_status`
  MODIFY `order_status_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- 使用表AUTO_INCREMENT `oc_order_total`
--
ALTER TABLE `oc_order_total`
  MODIFY `order_total_id` int(10) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=465;

--
-- 使用表AUTO_INCREMENT `oc_order_voucher`
--
ALTER TABLE `oc_order_voucher`
  MODIFY `order_voucher_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_paypal_order`
--
ALTER TABLE `oc_paypal_order`
  MODIFY `paypal_order_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_paypal_order_transaction`
--
ALTER TABLE `oc_paypal_order_transaction`
  MODIFY `paypal_order_transaction_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_product`
--
ALTER TABLE `oc_product`
  MODIFY `product_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=327;

--
-- 使用表AUTO_INCREMENT `oc_product_discount`
--
ALTER TABLE `oc_product_discount`
  MODIFY `product_discount_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_product_image`
--
ALTER TABLE `oc_product_image`
  MODIFY `product_image_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_product_option`
--
ALTER TABLE `oc_product_option`
  MODIFY `product_option_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=10;

--
-- 使用表AUTO_INCREMENT `oc_product_option_value`
--
ALTER TABLE `oc_product_option_value`
  MODIFY `product_option_value_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=35;

--
-- 使用表AUTO_INCREMENT `oc_product_reward`
--
ALTER TABLE `oc_product_reward`
  MODIFY `product_reward_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_product_special`
--
ALTER TABLE `oc_product_special`
  MODIFY `product_special_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_product_tag`
--
ALTER TABLE `oc_product_tag`
  MODIFY `product_tag_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '属性id', AUTO_INCREMENT=5;

--
-- 使用表AUTO_INCREMENT `oc_recurring`
--
ALTER TABLE `oc_recurring`
  MODIFY `recurring_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_return`
--
ALTER TABLE `oc_return`
  MODIFY `return_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_return_action`
--
ALTER TABLE `oc_return_action`
  MODIFY `return_action_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- 使用表AUTO_INCREMENT `oc_return_history`
--
ALTER TABLE `oc_return_history`
  MODIFY `return_history_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_return_reason`
--
ALTER TABLE `oc_return_reason`
  MODIFY `return_reason_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=6;

--
-- 使用表AUTO_INCREMENT `oc_return_status`
--
ALTER TABLE `oc_return_status`
  MODIFY `return_status_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- 使用表AUTO_INCREMENT `oc_review`
--
ALTER TABLE `oc_review`
  MODIFY `review_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=18;

--
-- 使用表AUTO_INCREMENT `oc_setting`
--
ALTER TABLE `oc_setting`
  MODIFY `setting_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=5662;

--
-- 使用表AUTO_INCREMENT `oc_shop_coupon`
--
ALTER TABLE `oc_shop_coupon`
  MODIFY `shop_coupon_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=12;

--
-- 使用表AUTO_INCREMENT `oc_shop_coupon_product`
--
ALTER TABLE `oc_shop_coupon_product`
  MODIFY `product_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- 使用表AUTO_INCREMENT `oc_shop_image`
--
ALTER TABLE `oc_shop_image`
  MODIFY `shop_image_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=865;

--
-- 使用表AUTO_INCREMENT `oc_shop_info`
--
ALTER TABLE `oc_shop_info`
  MODIFY `shop_info_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=177;

--
-- 使用表AUTO_INCREMENT `oc_shop_tag`
--
ALTER TABLE `oc_shop_tag`
  MODIFY `tag_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '标签id', AUTO_INCREMENT=9;

--
-- 使用表AUTO_INCREMENT `oc_shop_time`
--
ALTER TABLE `oc_shop_time`
  MODIFY `shop_time_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT COMMENT '时间表id', AUTO_INCREMENT=119;

--
-- 使用表AUTO_INCREMENT `oc_state`
--
ALTER TABLE `oc_state`
  MODIFY `state_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- 使用表AUTO_INCREMENT `oc_stock_status`
--
ALTER TABLE `oc_stock_status`
  MODIFY `stock_status_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- 使用表AUTO_INCREMENT `oc_store`
--
ALTER TABLE `oc_store`
  MODIFY `store_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_suburb`
--
ALTER TABLE `oc_suburb`
  MODIFY `suburb_id` int(11) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- 使用表AUTO_INCREMENT `oc_table_link`
--
ALTER TABLE `oc_table_link`
  MODIFY `link_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- 使用表AUTO_INCREMENT `oc_table_linksub`
--
ALTER TABLE `oc_table_linksub`
  MODIFY `linksub_id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_tax_class`
--
ALTER TABLE `oc_tax_class`
  MODIFY `tax_class_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=13;

--
-- 使用表AUTO_INCREMENT `oc_tax_rate`
--
ALTER TABLE `oc_tax_rate`
  MODIFY `tax_rate_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=90;

--
-- 使用表AUTO_INCREMENT `oc_tax_rule`
--
ALTER TABLE `oc_tax_rule`
  MODIFY `tax_rule_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_upload`
--
ALTER TABLE `oc_upload`
  MODIFY `upload_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=4;

--
-- 使用表AUTO_INCREMENT `oc_url_alias`
--
ALTER TABLE `oc_url_alias`
  MODIFY `url_alias_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=947;

--
-- 使用表AUTO_INCREMENT `oc_user`
--
ALTER TABLE `oc_user`
  MODIFY `id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- 使用表AUTO_INCREMENT `oc_user_group`
--
ALTER TABLE `oc_user_group`
  MODIFY `user_group_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=11;

--
-- 使用表AUTO_INCREMENT `oc_voucher`
--
ALTER TABLE `oc_voucher`
  MODIFY `voucher_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_voucher_history`
--
ALTER TABLE `oc_voucher_history`
  MODIFY `voucher_history_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_voucher_theme`
--
ALTER TABLE `oc_voucher_theme`
  MODIFY `voucher_theme_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=9;

--
-- 使用表AUTO_INCREMENT `oc_weight_class`
--
ALTER TABLE `oc_weight_class`
  MODIFY `weight_class_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- 使用表AUTO_INCREMENT `oc_weight_class_description`
--
ALTER TABLE `oc_weight_class_description`
  MODIFY `weight_class_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=7;

--
-- 使用表AUTO_INCREMENT `oc_zone`
--
ALTER TABLE `oc_zone`
  MODIFY `zone_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- 使用表AUTO_INCREMENT `oc_zone_to_geo_zone`
--
ALTER TABLE `oc_zone_to_geo_zone`
  MODIFY `zone_to_geo_zone_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=130;

--
-- 使用表AUTO_INCREMENT `users`
--
ALTER TABLE `users`
  MODIFY `id` int(10) UNSIGNED NOT NULL AUTO_INCREMENT;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
