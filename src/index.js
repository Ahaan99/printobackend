import React, { useEffect, useState } from "react";
import { useAuth } from "@/context/AuthContext";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import { motion } from "framer-motion";
import { FiEdit2 } from "react-icons/fi";
import { BsBoxSeam } from "react-icons/bs";
import { MdOutlineInventory2 } from "react-icons/md";
import { PiTShirt } from "react-icons/pi";
import { cn } from "@/lib/utils";
import productApi from "@/api/productApi";
import { toast } from "sonner";
import { sampleProducts } from "@/data/sampleProducts";
import { useNavigate } from "react-router-dom";

const ProductCard = ({ product, onCustomize }) => (
  <motion.div
    initial={{ opacity: 0, y: 30 }}
    animate={{ opacity: 1, y: 0 }}
    whileHover={{
      scale: 1.025,
      boxShadow: "0 8px 32px 0 rgba(60,60,120,0.10)",
    }}
    transition={{ duration: 0.25, ease: "easeOut" }}
    className="flex flex-col bg-background rounded-2xl shadow-sm border border-border overflow-hidden group transition-all"
  >
    <div className="relative h-56 bg-muted flex items-center justify-center overflow-hidden">
      <img
        src={product.images?.[0]?.url}
        alt={product.name}
        className="object-contain w-full h-full transition-transform duration-300 group-hover:scale-105"
        loading="lazy"
      />
      {product.stock > 0 ? (
        <Badge
          className="absolute top-3 left-3 bg-green-500 text-white shadow"
          variant="secondary"
        >
          <MdOutlineInventory2 className="inline mr-1 -mt-0.5" />
          In Stock
        </Badge>
      ) : (
        <Badge
          className="absolute top-3 left-3 bg-red-500 text-white shadow"
          variant="secondary"
        >
          Out of Stock
        </Badge>
      )}
    </div>
    <CardContent className="flex flex-col flex-1 p-5">
      <div className="flex justify-between items-center mb-1">
        <h3
          className="font-semibold text-lg truncate max-w-[70%] text-ellipsis"
          title={product.name}
        >
          {product.name}
        </h3>
        <span className="font-bold text-lg text-primary ml-2 whitespace-nowrap">
          ${Number(product.price).toFixed(2)}
        </span>
      </div>
      <p className="text-muted-foreground text-sm mb-3 line-clamp-2">
        {product.description}
      </p>
      <div className="flex flex-wrap gap-2 mb-3">
        {product.sizes?.map((size) => (
          <Badge
            key={size}
            variant="outline"
            className="rounded px-2 py-1 text-xs border border-gray-300 bg-background"
          >
            {size}
          </Badge>
        ))}
      </div>
      {product.colors?.length > 0 && (
        <div className="flex gap-1 mb-4">
          {product.colors.map((color, idx) => (
            <span
              key={color + idx}
              className={cn(
                "w-6 h-6 rounded-full border-2 border-gray-200 inline-block",
                color.toLowerCase() === "white" ? "border-gray-300" : ""
              )}
              style={{ backgroundColor: color }}
              title={color}
            />
          ))}
        </div>
      )}
      <div className="flex-1" />
      <Button
        variant="default"
        size="lg"
        className="w-full mt-2 flex items-center justify-center gap-2 bg-indigo-600 hover:bg-indigo-700 transition"
        onClick={() => onCustomize(product._id)}
        disabled={product.stock <= 0}
        asChild={false}
      >
        <FiEdit2 className="text-lg" />
        Customize Now
      </Button>
    </CardContent>
  </motion.div>
);

const Customizable_Products = () => {
  const { products, setProducts } = useAuth();
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  // Fetch products if not present
  useEffect(() => {
    if (!products || products.length === 0) {
      const fetchProducts = async () => {
        try {
          setLoading(true);
          const response = await productApi.get("/");
          console.log("Fetched products:", response.data);
          setProducts(response.data);
          console.log("[DEBUG] Products fetched from backend:", response.data);
        } catch (error) {
          console.error("Error fetching products:", error);
          toast.error("Failed to load products");
          setProducts(sampleProducts);
          console.log("[DEBUG] Using sampleProducts:", sampleProducts);
        } finally {
          setLoading(false);
        }
      };
      fetchProducts();
    }
  }, [products, setProducts]);

  const customizableProducts = (products || []).filter((p) => p.customizable);

  const handleCustomize = (id) => {
    const product = (products || []).find((p) => p._id === id);
    if (product) {
      navigate(`/customizable/${id}`, { state: { product } });
    } else {
      navigate(`/customizable/${id}`);
    }
  };

  return (
    <div className="container max-w-7xl mx-auto px-4 py-8">
      <motion.div
        initial={{ opacity: 0, y: -20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4, ease: "easeOut" }}
        className="flex items-center justify-between mb-8"
      >
        <div>
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white mb-1 tracking-tight">
            Customizable Products
          </h1>
          <p className="text-muted-foreground text-base">
            Personalize your style with our premium customizable collection.
          </p>
        </div>
        <BsBoxSeam className="text-4xl text-indigo-500 hidden md:block" />
      </motion.div>
      {loading ? (
        <div className="flex justify-center items-center py-16">
          <div className="animate-spin h-8 w-8 border-4 border-indigo-600 border-t-transparent rounded-full mr-4"></div>
          <span className="text-gray-500 dark:text-gray-400">
            Loading products...
          </span>
        </div>
      ) : customizableProducts.length === 0 ? (
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          className="text-gray-500 dark:text-gray-400 text-center py-16"
        >
          No customizable products found.
        </motion.div>
      ) : (
        <motion.div
          initial="hidden"
          animate="visible"
          variants={{
            hidden: {},
            visible: {
              transition: {
                staggerChildren: 0.08,
              },
            },
          }}
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-8"
        >
          {customizableProducts.map((product) => (
            <ProductCard
              key={product._id}
              product={product}
              onCustomize={handleCustomize}
            />
          ))}
        </motion.div>
      )}
    </div>
  );
};

export default Customizable_Products;
